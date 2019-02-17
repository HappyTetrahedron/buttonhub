from flask import Flask
from flask import request
import yaml
import requests
from optparse import OptionParser


app = Flask(__name__)

config = None


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
        print("No button config found")
        return ""

    endpoints = button_config.get(action)
    if not endpoints:
        print("No endpoints found")
        return ""

    state_key = '{}state'.format(action)
    if state_key in button_config:
        state_id = button_config[state_key]
        state_id = (state_id + 1) % len(endpoints)
    else:
        state_id = 0

    next_state = endpoints[state_id]

    url = next_state.get('url')
    if not url:
        print("No URL defined")
        return ""
    if '{battery}' in url or '{device}' in url:
        url = url.format(battery=str(battery), device=str(device_id))

    method = next_state.get('method') or 'get'
    headers = next_state.get('headers')
    data = next_state.get('payload')
    if data:
        if '{battery}' in data or '{device}' in data:
            data = data.format(battery=str(battery), device=str(device_id))

    print(data)
    response = requests.request(method, url, data=data, headers=headers)
    print(response.text)

    button_config[state_key] = state_id

    return ""


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-c', '--config', dest='config', default='config.yml', type='string',
                      help="Path of configuration file")
    (opts, args) = parser.parse_args()
    with open(opts.config, 'r') as configfile:
        config = yaml.load(configfile)
    app.run(config['host'], config['port'])
