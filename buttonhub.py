#!/usr/bin/env python

import datetime
import json
from optparse import OptionParser

import paho.mqtt.client as mqtt
import requests
import yaml
from flask import Flask
from flask import request

app = Flask(__name__)
state = {}
client = None

config = None

CAROUSEL = 'carousel'
FLOOD = 'flood'
CONDITION_ALL = 'condition_all'
CONDITION_FIRST = 'condition_first'


@app.route("/device/<device_id>")
def handle_request(device_id):
    action = request.args.get('action')
    battery = request.args.get('battery')

    action = 'single' if action == '1' else \
             'double' if action == '2' else \
             'long' if action == '3' else \
             'touch' if action == '4' else \
             'wheel' if action == '5' else \
             'wheel_final' if action == '11' else \
             'battery' if action == '6' else \
             'not_found'

    button_config = config['buttons'].get(device_id)
    if not button_config:
        print("No button config found for {}".format(device_id))
        return ""

    action_config = button_config.get(action)
    if not action_config:
        print("No config found for {}".format(action))
        return ""

    do_action(action_config, action, battery, device_id)

    return ""


def handle_mqtt(_client, userdata, message):
    parsed_payload = json.loads(message.payload.decode("UTF-8"))
    topic = message.topic
    action = "default"

    state[topic] = parsed_payload

    button_config = config['topics'].get(topic)
    if not button_config:
        print("No topic config found for {}".format(topic))
        return

    action_key = button_config.get("action_key", "action")
    if parsed_payload:
        action = parsed_payload.get(action_key, "default")

    action_config = button_config.get(action)
    if not action_config:
        print("No action config found for {}".format(action))
        return

    do_action(action_config, action, topic, None)


def do_action(action_config, action, device_id, battery):
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
        do_request(next_state, battery, device_id)
        action_config[state_key] = state_id

    if mode == FLOOD:
        for req in actions:
            do_request(req, battery, device_id)

    if mode in [CONDITION_ALL, CONDITION_FIRST]:
        for req in actions:
            do_it = True
            if 'condition' in req:
                do_it = check_condition(req['condition'], battery, device_id)
            if do_it:
                print("Performing request due to condition match")
                do_request(req, battery, device_id)
                if mode == CONDITION_FIRST:
                    return


def check_condition(condition, battery, device_id, carry_value=None):
    passes = True
    if not isinstance(condition, dict):
        return carry_value == condition
    if 'battery' in condition:
        passes = passes and check_condition(condition['battery'], battery, device_id, battery)
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
        passes = passes and all([check_condition(c, battery, device_id, carry_value) for c in condition['and']])
    if 'or' in condition:
        passes = passes and any([check_condition(c, battery, device_id, carry_value) for c in condition['or']])
    if 'request' in condition:
        req = condition['request']
        response = do_http(req, battery, device_id)
        if 'response' in req:
            for response_condition in req['response']:
                passes = passes and check_data_condition(response_condition, response.json(), battery, device_id)
        else:
            passes = passes and response.status_code // 100 == 2
    if 'state' in condition:
        condition = condition['state']
        passes = passes and check_data_condition(condition, state.get(condition['topic'], {}), battery, device_id)
    if 'lt' in condition:
        passes = passes and int(carry_value) < condition['lt']
    if 'gt' in condition:
        passes = passes and int(carry_value) > condition['gt']
    return passes


def check_data_condition(condition, data, battery, device_id):
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
        passes = passes and check_condition(condition['value'], battery, device_id, current_part)
    return passes


def do_request(req, battery, device_id):
    if 'endpoints' in req:
        for sub_req in req['endpoints']:
            do_request(sub_req, battery, device_id)
    if 'url' in req:
        do_http(req, battery, device_id)
    if 'topic' in req:
        do_mqtt(req, battery, device_id, client)


def do_http(req, battery, device_id):
    url = req.get('url')
    if not url:
        print("No URL defined")
        return ""
    if '{battery}' in url or '{device}' in url:
        url = url.format(battery=str(battery), device=str(device_id))

    method = req.get('method') or 'get'
    headers = req.get('headers')
    data = req.get('payload')
    if data:
        if '{battery}' in data or '{device}' in data:
            data = data.format(battery=str(battery), device=str(device_id))

    return requests.request(method, url, data=data, headers=headers)


def do_mqtt(req, battery, device_id, _client):
    topic = req.get('topic')
    if not topic:
        print("No topic defined")
        return
    payload = req.get('payload')

    if payload:
        if '{battery}' in payload or '{device}' in payload:
            payload = payload.format(battery=str(battery), device=str(device_id))

    print("publish")
    _client.publish(topic, payload)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-c', '--config', dest='config', default='config.yml', type='string',
                      help="Path of configuration file")
    (opts, args) = parser.parse_args()
    with open(opts.config, 'r') as configfile:
        config = yaml.load(configfile)

    client = mqtt.Client("buttonhub")
    client.connect(config['broker'])
    client.on_message = handle_mqtt
    client.subscribe("#")
    client.loop_start()
    app.run(config['host'], config['port'])
    client.loop_stop()
