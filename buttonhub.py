#!/usr/bin/env python

from flask import Flask
from flask import request
import yaml
import requests
import datetime
from optparse import OptionParser


app = Flask(__name__)

config = None

CAROUSEL = 'carousel'
FLOOD = 'flood'
CONDITION_ALL = 'condition_all'
CONDITION_FIRST = 'condition_first'


@app.route("/device/<device_id>")
def handle_action(device_id):
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

    actions = action_config.get('actions')
    if not actions:
        print("No actions found for {}".format(action))
        return ""

    mode = action_config.get('mode') or FLOOD

    if mode == CAROUSEL:
        state_key = 'state'
        if state_key in action_config:
            state_id = action_config[state_key]
            state_id = (state_id + 1) % len(actions)
        else:
            state_id = 0

        next_state = actions[state_id]
        response = do_request(next_state, battery, device_id)
        print(response.text)
        action_config[state_key] = state_id

    if mode == FLOOD:
        for req in actions:
            response = do_request(req, battery, device_id)
            print(response.text)

    if mode in [CONDITION_ALL, CONDITION_FIRST]:
        for req in actions:
            do_it = True
            if 'condition' in req:
                do_it = check_condition(req['condition'], battery, device_id)
            if do_it:
                print("Performing request due to condition match")
                response = do_request(req, battery, device_id)
                print(response.text)
                if mode == CONDITION_FIRST:
                    return ""

    return ""


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
        response = do_request(req, battery, device_id)
        if 'response' in req:
            for response_condition in req['response']:
                if 'path' in response_condition:
                    path = response_condition['path']
                    path = path.split('.')
                    current_part = response.json()
                    for key in path:
                        if key not in current_part:
                            passes = False
                        else:
                            current_part = current_part[key]
                    if 'value' in response_condition:
                        passes = passes and check_condition(response_condition['value'], battery, device_id, current_part)
        else:
            passes = passes and response.status_code // 100 == 2
    if 'lt' in condition:
        passes = passes and int(carry_value) < condition['lt']
    if 'gt' in condition:
        passes = passes and int(carry_value) > condition['gt']
    return passes


def do_request(req, battery, device_id):
    if 'endpoints' in req:
        last_response = None
        for sub_req in req['endpoints']:
            last_response = do_request(sub_req, battery, device_id)
        return last_response
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


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-c', '--config', dest='config', default='config.yml', type='string',
                      help="Path of configuration file")
    (opts, args) = parser.parse_args()
    with open(opts.config, 'r') as configfile:
        config = yaml.load(configfile)
    app.run(config['host'], config['port'])
