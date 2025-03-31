#!/usr/bin/env python
import datetime
import json
import os
import threading
import time
from optparse import OptionParser
from astral import geocoder
from astral import sun as astral_sun
import pytz
import re

import paho.mqtt.client as mqtt
import requests
import yaml
from flask import Flask
from flask import request

app = Flask(__name__)
app_state = {}
device_status = {}
mqtt_client = None
scheduled_flows = []

scheduler_events = threading.Event()
scheduler_event = threading.Event()

config = None
city = geocoder.lookup('Bern', geocoder.database())
timezone = pytz.timezone('Europe/Zurich')
ignore_topics_regex = None

CAROUSEL = 'carousel'
FLOOD = 'flood'
CONDITION_ALL = 'condition_all'
CONDITION_FIRST = 'condition_first'

STARTUP_FLOW_NAME = 'startup'

METRIC_PREFIX = "buttonhub"
VALID_METRIC_TYPES = ['gauge', 'counter']

ACTIONS = {
    '1': 'single',
    '2': 'double',
    '3': 'long',
    '4': 'touch',
    '5': 'wheel',
    '6': 'battery',
    '8': 'rise',
    '9': 'fall',
    '11': 'wheel_final',
    '14': 'night',
    '15': 'twilight',
    '16': 'day',
}

STATE_FILE = 'buttonhub-state.json'
STATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def log(message):
    print(message, flush=True)


def _get_action(request_args):
    return ACTIONS.get(request_args.get('action'), 'not_found')


def _get_context_for_device_request(device_id, request_args):
    return {
        'device_id': device_id,
        'battery': request_args.get('battery'),
        'time': str(datetime.datetime.now()),
    }


def _update_device_status(device_id, context):
    device_status[device_id] = {
        'last_seen': str(datetime.datetime.now()),
        'battery': context.get('battery'),
    }


def _get_context_for_mqtt_message(topic, payload):
    return {
        'topic': topic,
        'battery': payload.get('battery'),
        'time': str(datetime.datetime.now()),
    }


def _apply_context_to_template(template, context):
    if isinstance(template, dict):
        new = {}
        for k, v in template.items():
            new[k] = _apply_context_to_template(v, context)
        return new

    if isinstance(template, str):
        for key in context:
            placeholder = '{{{key}}}'.format(key=key)
            if placeholder in template:
                template = template.replace(placeholder, str(context[key]))
    return template


@app.route('/device/<device_id>')
def handle_request(device_id):
    action = _get_action(request.args)
    context = _get_context_for_device_request(device_id, request.args)

    _update_device_status(device_id, context)

    device_config = config.get('devices', {}).get(device_id)
    if not device_config:
        log("No device config found for {}".format(device_id))
        return ''

    action_config = device_config.get(action)
    if not action_config:
        log("No config found for {}".format(action))
        return ''

    do_action(action_config, action, context)

    return ''


@app.route('/status')
def get_status():
    return {
        'devices': device_status,
        'schedules': scheduled_flows,
    }


@app.route('/state')
def get_state():
    return app_state


@app.route('/dump_state', methods=['POST'])
def dump_state():
    with open(STATE_FILE, 'w', encoding='utf-8') as file:
        json.dump(
            {
                "state": app_state,
                "schedules": [
                    {
                        'name': s['name'],
                        'time': s['time'].strftime(STATE_TIME_FORMAT),
                    }
                    for s in scheduled_flows
                ],
                "time": datetime.datetime.now().strftime(STATE_TIME_FORMAT),
            },
            file,
        )
    return 'ok'


@app.route('/metrics')
def get_metrics():
    metric_text = ""
    for metric in config.get("metrics", []):
        m_name = f"{METRIC_PREFIX}_{metric['name']}"
        m_help = metric.get('help', "A buttonhub metric.")
        m_type = metric.get('type', 'gauge')
        if m_type not in VALID_METRIC_TYPES:
            m_type = 'gauge'
        metric_text += f"# HELP {m_name} {m_help}\n"
        metric_text += f"# TYPE {m_name} {m_type}\n"

        m_default_path = metric.get('path', None)

        for ts in metric.get("measurements", []):
            s = app_state.get(ts['topic'], {})
            v = get_value_by_path(s, ts.get('path', m_default_path))
            if v is None:
                continue
            v = make_metric_value(v)
            if ts.get('labels', None):
                metric_text += ("{}{{{}}} {}\n".format(
                    m_name,
                    ','.join([f'"{l}"="{v}"' for l, v in ts['labels'].items()]),
                    v
                ))
            else:
                metric_text += f"{m_name} {v}\n"

    return Response(metric_text, mimetype="text/plain")

def make_metric_name(topic, path):
    t = topic.split('/')
    p = path.split('.')
    return f"{t}_{p}"

def make_metric_value(raw):
    if raw in ['ON', 'true', 'True', True]:
        return '1'
    if raw in ['OFF', 'false', 'False', False]:
        return '0'
    try:
        float(raw)
        return raw
    except:
        return '-1'

@app.route('/flows')
def get_flows():
    flows = config.get('flows', {})
    return {
        'flows': [
            {
                'name': flow_name,
                'label': flows[flow_name].get('label') or flow_name,
                'group': flows[flow_name].get('group') or 'default',
                'hidden': flows[flow_name].get('hidden') or False,
            }
            for flow_name in flows
        ],
    }


@app.route('/flows/<flow_name>', methods=['POST'])
def run_flow(flow_name):
    do_flow(flow_name, context={
        'agent': request.headers.get('User-Agent'),
        'flow': flow_name,
        'time': str(datetime.datetime.now()),
    })
    return ''


def handle_mqtt(_client, userdata, message):
    topic = message.topic

    try:
        parsed_payload = json.loads(message.payload.decode('UTF-8'))
    except json.decoder.JSONDecodeError:
        log("Unexpected payload for topic {}: {}".format(message.topic, message.payload))
        return
    action = 'default'

    previous_topic_state = app_state.get(topic)
    if not ignore_topics_regex or not re.search(ignore_topics_regex, topic):
        parsed_payload['last_seen'] = str(datetime.datetime.now())
        app_state[topic] = parsed_payload
    topics_config = None
    if 'topics' in config:
        topics_config = config['topics'].get(topic)
    if not topics_config:
        return

    action_key = topics_config.get('action_key', 'action')
    if parsed_payload:
        action = parsed_payload.get(action_key, 'default')
        if isinstance(action, str):
            action = action.lower()

    action_config = topics_config.get(action)
    if not action_config:
        if action != 'default':
            log("No action config found for topic {} with action {}".format(topic, action))
        return

    if topics_config.get('ignore_repetition') and parsed_payload and (previous_topic_state or {}).get(action_key) == parsed_payload.get(action_key):
        log("Skipping topic {} with action {}={}, ignoring repetition".format(topic, action_key, action))
        return

    log("Handling topic {} with action {}={}".format(topic, action_key, action))

    context = _get_context_for_mqtt_message(topic, parsed_payload)

    do_action(action_config, action, context)


def do_action(action_config, action, context):
    actions = action_config.get('actions')
    if not actions:
        log("No actions found for {}".format(action))
        return

    mode = action_config.get('mode') or FLOOD

    if mode == CAROUSEL:
        state_key = 'state'
        if state_key in action_config:
            state_id = action_config[state_key]
            state_id = (state_id + 1) % len(actions)
        else:
            state_id = 0

        next_state = actions[state_id]
        do_request(next_state, context)
        action_config[state_key] = state_id

    if mode == FLOOD:
        for req in actions:
            do_request(req, context)

    if mode in [CONDITION_ALL, CONDITION_FIRST]:
        for req in actions:
            do_it = True
            if 'condition' in req:
                do_it = check_condition(req['condition'], context)
            if do_it:
                log("Performing request due to condition match")
                do_request(req, context)
                if mode == CONDITION_FIRST:
                    return


def check_condition(condition, context, carry_value=None):
    passes = True
    if not isinstance(condition, dict):
        return carry_value == condition
    if 'battery' in condition:
        passes = passes and check_condition(condition['battery'], context, carry_value=context['battery'])
    if 'time' in condition:
        now = datetime.datetime.now().time()
        time = condition['time']
        # handle gt and lt separately for time as it is a special data type
        if 'lt' in time:
            h, m = parse_time(time['lt'])
            passes = passes and (now.hour < h or (now.hour == h and now.minute < m))
        if 'gt' in time:
            h, m = parse_time(time['gt'])
            passes = passes and (now.hour > h or (now.hour == h and now.minute > m))
    if 'and' in condition:
        passes = passes and all([check_condition(c, context, carry_value) for c in condition['and']])
    if 'or' in condition:
        passes = passes and any([check_condition(c, context, carry_value) for c in condition['or']])
    if 'not' in condition:
        passes = passes and not check_condition(condition['not'], context, carry_value)
    if 'request' in condition:
        req = condition['request']
        response = do_http(req, context)
        if 'response' in req:
            for response_condition in req['response']:
                passes = passes and check_data_condition(response_condition, response.json(), context)
        else:
            passes = passes and response.status_code // 100 == 2
    if 'state' in condition:
        condition = condition['state']
        passes = passes and check_data_condition(condition, app_state.get(condition['topic'], {}), context)
    if 'lt' in condition:
        passes = passes and int(carry_value) < condition['lt']
    if 'gt' in condition:
        passes = passes and int(carry_value) > condition['gt']
    return passes


def parse_time(time_string):
    if ':' in time_string:
        parts = time_string.split(':')
        return int(parts[0]), int(parts[1])
    if time_string.startswith('sunrise'):
        base_time = get_astral_time('sunrise')
        time_string = time_string[7:]
    elif time_string.startswith('sunset'):
        base_time = get_astral_time('sunset')
        time_string = time_string[6:]
    else:
        raise 'Invalid time {}'.format(time_string)
    parsed_time = base_time + parse_time_offset(time_string)
    return parsed_time.hour, parsed_time.minute


def get_astral_time(key):
    return astral_sun.sun(city.observer, date=datetime.datetime.now())[key] \
        .replace(tzinfo=pytz.utc) \
        .astimezone(timezone)


def parse_time_offset(time_offset_string):
    if time_offset_string == '':
        offset = 0
    else:
        offset = int(time_offset_string)
    return datetime.timedelta(minutes=offset)


def check_data_condition(condition, data, context):
    v = get_value_by_path(data, condition['path'])
    passes = v is not None and check_condition(condition['value'], context, carry_value=v)
    return passes

def get_value_by_path(data, path):
    path = path.split('.')
    current_part = data
    for key in path:
        if key not in current_part:
            return None
        else:
            current_part = current_part[key]
    return current_part

def do_request(req, context):
    if 'delay' in req:
        time.sleep(req['delay'])
    if 'group' in req:
        for sub_req in req['group']:
            do_request(sub_req, context)
    if 'url' in req:
        try:
            do_http(req, context)
        except Exception as e:
            log("Failed to perform HTTP request to {}".format(req.get('url')))
            log(e)
    if 'topic' in req:
        if mqtt_client is None:
            return
        do_mqtt(req, context, mqtt_client)
    if 'flow' in req:
        flow_name = req.get('flow', '')
        do_flow(flow_name, context)
    if 'schedule-flow' in req:
        schedule_flow(req, context)
    if 'cancel-scheduled-flow' in req:
        cancel_scheduled_flow(req, context)
    if 'set-state' in req:
        do_set_state(req, context)
    if 'increment-state' in req:
        do_increment_state(req, context)


def do_http(req, context):
    url = req.get('url')
    if not url:
        log("No URL defined")
        return ''
    url = _apply_context_to_template(url, context)

    method = req.get('method') or 'get'
    headers = req.get('headers')
    data = req.get('payload')
    if data:
        data = _apply_context_to_template(data, context)

    return requests.request(method, url, data=data, headers=headers)


def do_mqtt(req, context, _client):
    topic = req.get('topic')
    if not topic:
        log("No topic defined")
        return
    payload = req.get('payload')

    if payload:
        payload = _apply_context_to_template(payload, context)

    _client.publish(topic, payload)


def do_flow(flow_name, context):
    flow = config.get('flows', {}).get(flow_name)
    if not flow:
        log("No Flow defined for '{}'".format(flow_name))
        return ''
    do_action(flow, flow_name, context)


def schedule_flow(req, context):
    global scheduled_flows
    flow_name = req.get('schedule-flow', '')
    schedule_time = None
    if 'interval' in req:
        timedelta = _parse_time_interval(req['interval'])
        schedule_time = datetime.datetime.now() + timedelta
    if 'time' in req:
        h, m = parse_time(req['time'])
        now = datetime.datetime.now()
        schedule_time = now.replace(hour=h, minute=m)
        if now > schedule_time:
            schedule_time = schedule_time + datetime.timedelta(days=1)
    if not schedule_time:
        return

    log("Scheduling flow '{}' to run at {}".format(flow_name, schedule_time))

    scheduled_flows.append({
        'name': flow_name,
        'time': schedule_time,
        'context': context,
    })
    scheduler_event.set()


def _parse_time_interval(interval_string):
    parts = interval_string.split(':')
    hours = 0
    minutes = 0
    if len(parts) == 2:
        hours = int(parts[0])
        minutes = int(parts[1])
    elif len(parts) == 1:
        minutes = int(parts[0])
    return datetime.timedelta(hours=hours, minutes=minutes)


def cancel_scheduled_flow(req, context):
    global scheduled_flows
    flow_name = req.get('cancel-scheduled-flow', '')
    log("Cancelling scheduled flow '{}'".format(flow_name))
    scheduled_flows = [entry for entry in scheduled_flows if entry['name'] != flow_name]


def run_scheduled_flows():
    global scheduled_flows
    now = datetime.datetime.now()
    due_flows = [flow for flow in scheduled_flows if flow['time'] < now]
    for flow in due_flows:
        flow_name = flow['name']
        original_context = flow.get('context')
        log('Running scheduled flow {} (context={})'.format(flow_name, original_context))
        do_flow(flow_name, context={})
    if due_flows:
        scheduled_flows = [flow for flow in scheduled_flows if flow['time'] >= now]


def do_set_state(req, context):
    key = req.get('set-state')
    value = req.get('new-state')
    value = _apply_context_to_template(value, context)
    value['context'] = context
    app_state[key] = value
    log("Set state for {} to {}".format(key, value))


def do_increment_state(req, context):
    topic = req.get('increment-state')
    path = req.get('path') # TODO: Add support for multi-level paths?
    data = app_state.get(topic, {})
    value = {
        path: int(get_value_by_path(data, path) or 0) + 1,
    }
    value = _apply_context_to_template(value, context)
    app_state[topic] = value


def scheduler():
    error_count = 0
    while not scheduler_events.is_set() and error_count < 100:
        try:
            scheduler_event.clear()
            run_scheduled_flows()
            scheduler_event.wait(60)
            error_count = 0
        except Exception as e:
            error_count = error_count + 1
            log("Error in scheduling thread (#{})".format(error_count))
            log(e)


def _on_mqtt_log_message(client, userdata, level, buf):
    if level == mqtt.MQTT_LOG_ERR:
        log("MQTT error: {}".format(buf))


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option(
        '-c',
        '--config',
        dest='config',
        default='config.yml',
        type='string',
        help="Path of configuration file",
    )
    (opts, args) = parser.parse_args()
    with open(opts.config, 'r') as configfile:
        config = yaml.load(configfile, Loader=yaml.Loader)
        if 'location' in config:
            city = geocoder.lookup(config['location'], geocoder.database())
        if 'timezone' in config:
            timezone = pytz.timezone(config['timezone'])
        if 'ignore-topics' in config:
            ignore_topics_regex = config['ignore-topics']

    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as state_file:
                loaded_state = json.load(state_file)
                now = datetime.datetime.now()
                loaded_state_time = datetime.datetime.strptime(loaded_state['time'], STATE_TIME_FORMAT)
                if (now - loaded_state_time) < datetime.timedelta(minutes=2):
                    app_state = loaded_state['state']
                    scheduled_flows = [
                        {
                            'name': s['name'],
                            'time': datetime.datetime.strptime(s['time'], STATE_TIME_FORMAT),
                            'context': {
                                'restored_at': str(now),
                            },
                        }
                        for s in loaded_state['schedules']
                    ]
                    log("Loaded state from file")
                else:
                    log("Skipping restoring state from stale file")
            os.remove(STATE_FILE)
    except Exception as e:
        log("Skipping restoring state from file: {}".format(e))


    scheduler_thread = threading.Thread(target=scheduler)
    scheduler_thread.start()

    if 'broker' in config:
        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, 'buttonhub')
        if 'userauth' in config['broker']:
            mqtt_client.username_pw_set(
                config['broker']['userauth']['user'],
                password=config['broker']['userauth']['password'],
            )
        mqtt_client.on_log = _on_mqtt_log_message
        mqtt_client.on_message = handle_mqtt
        mqtt_client.connect(config['broker']['host'], config['broker']['port'])
        mqtt_client.subscribe(config['broker'].get('subscribe', '#'))
        mqtt_client.loop_start()

    startup_flow = config.get('flows', {}).get(STARTUP_FLOW_NAME, None)
    if startup_flow:
        log("Running startup flow")
        do_flow(STARTUP_FLOW_NAME, {'startup': True, 'time': str(datetime.datetime.now())})
    app.run(config['host'], config['port'])

    scheduler_events.set()
    scheduler_event.set()
    if 'broker' in config:
        mqtt_client.loop_stop()
