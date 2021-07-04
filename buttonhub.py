#!/usr/bin/env python

import datetime
import json
import time
from optparse import OptionParser

import paho.mqtt.client as mqtt
import requests
import yaml
from flask import Flask
from flask import request

app = Flask(__name__)
state = {}
mqtt_client = None

config = None

CAROUSEL = 'carousel'
FLOOD = 'flood'
CONDITION_ALL = 'condition_all'
CONDITION_FIRST = 'condition_first'

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


def _get_action(request_args):
    return ACTIONS.get(request_args.get('action'), 'not_found')


def _get_context_for_device_request(device_id, request_args):
    return {
        'device_id': device_id,
        'battery': request_args.get('battery'),
    }


def _get_context_for_mqtt_message(message):
    return {
        'topic': message.topic,
    }


def _apply_context_to_template(template, context):
    for key in context:
        placeholder = '{{{key}}}'.format(key=key)
        if placeholder in template:
            template = template.replace(placeholder, str(context[key]))
    return template


@app.route('/device/<device_id>')
def handle_request(device_id):
    action = _get_action(request.args)
    context = _get_context_for_device_request(device_id, request.args)

    device_config = config.get('devices', config.get('buttons', {})).get(device_id)
    if not device_config:
        print("No device config found for {}".format(device_id))
        return ''

    action_config = device_config.get(action)
    if not action_config:
        print("No config found for {}".format(action))
        return ''

    do_action(action_config, action, context)

    return ''


def handle_mqtt(_client, userdata, message):
    parsed_payload = json.loads(message.payload.decode('UTF-8'))
    topic = message.topic
    action = 'default'

    state[topic] = parsed_payload

    topics_config = config['topics'].get(topic)
    if not topics_config:
        print("No topic config found for {}".format(topic))
        return

    action_key = topics_config.get('action_key', 'action')
    if parsed_payload:
        action = parsed_payload.get(action_key, 'default')

    action_config = topics_config.get(action)
    if not action_config:
        print("No action config found for {}".format(action))
        return

    context = _get_context_for_mqtt_message(message)

    do_action(action_config, action, context)


def do_action(action_config, action, context):
    actions = action_config.get('actions')
    if not actions:
        print("No actions found for {}".format(action))
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
                print("Performing request due to condition match")
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
            h, m = tuple(time['lt'].split(':'))
            passes = passes and (now.hour < int(h) or (now.hour == int(h) and now.minute < int(m)))
        if 'gt' in time:
            h, m = tuple(time['gt'].split(':'))
            passes = passes and (now.hour > int(h) or (now.hour == int(h) and now.minute > int(m)))
    if 'and' in condition:
        passes = passes and all([check_condition(c, context, carry_value) for c in condition['and']])
    if 'or' in condition:
        passes = passes and any([check_condition(c, context, carry_value) for c in condition['or']])
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
        passes = passes and check_data_condition(condition, state.get(condition['topic'], {}), context)
    if 'lt' in condition:
        passes = passes and int(carry_value) < condition['lt']
    if 'gt' in condition:
        passes = passes and int(carry_value) > condition['gt']
    return passes


def check_data_condition(condition, data, context):
    passes = True
    path = condition['path']
    path = path.split('.')
    current_part = data
    for key in path:
        if key not in current_part:
            passes = False
        else:
            current_part = current_part[key]
    if 'value' in condition:
        passes = passes and check_condition(condition['value'], context, carry_value=current_part)
    return passes


def do_request(req, context):
    if 'delay' in req:
        time.sleep(req['delay'])
    if 'endpoints' in req:
        for sub_req in req['endpoints']:
            do_request(sub_req, context)
    if 'url' in req:
        do_http(req, context)
    if 'topic' in req:
        if mqtt_client is None:
            return
        do_mqtt(req, context, mqtt_client)


def do_http(req, context):
    url = req.get('url')
    if not url:
        print("No URL defined")
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
        print("No topic defined")
        return
    payload = req.get('payload')

    if payload:
        payload = _apply_context_to_template(payload, context)

    _client.publish(topic, payload)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-c', '--config', dest='config', default='config.yml', type='string',
                      help="Path of configuration file")
    (opts, args) = parser.parse_args()
    with open(opts.config, 'r') as configfile:
        config = yaml.load(configfile)

    if 'broker' in config:
        mqtt_client = mqtt.Client('buttonhub')
        if 'userauth' in config['broker']:
            mqtt_client.username_pw_set(
                config['broker']['userauth']['user'],
                password=config['broker']['userauth']['password'],
            )
        mqtt_client.on_message = handle_mqtt
        mqtt_client.connect(config['broker']['host'], config['broker']['port'])
        mqtt_client.subscribe(config['broker'].get('subscribe', '#'))
        mqtt_client.loop_start()
    app.run(config['host'], config['port'])

    if 'broker' in config:
        mqtt_client.loop_stop()
