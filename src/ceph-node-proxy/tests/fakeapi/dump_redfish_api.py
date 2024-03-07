import json
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from ceph_node_proxy.redfish_client import RedFishClient
from typing import Any, Dict, Optional, Set

DEFAULT_HOSTNAME: str = '127.0.0.1'
DEFAULT_PORT: str = '443'
DEFAULT_USERNAME: str = 'admin'
DEFAULT_PASSWORD: str = 'password'
DEFAULT_DUMP_DIRECTORY: str = os.path.join(os.getcwd(), 'dump')


def get_odata_ids(data: Dict[str, Any],
                  output: str,
                  client: RedFishClient,
                  visited: Optional[Set] = None) -> None:
    if visited is None:
        visited = set()
    if isinstance(data, dict):
        if '@odata.id' in data:
            endpoint = data['@odata.id']
            if endpoint not in visited:
                visited.add(endpoint)
                try:
                    response = client.query(endpoint=endpoint, retries=3, delay=3)[1]
                    path = os.path.join(output, endpoint[1:].replace('/', '+'))
                    with open(path, 'w') as f:
                        f.write(response)
                    response_json = json.loads(response)
                    get_odata_ids(response_json, output, client, visited)
                except Exception as e:
                    print(e)
        for value in data.values():
            get_odata_ids(value, output, client, visited)
    elif isinstance(data, list):
        for item in data:
            get_odata_ids(item, output, client, visited)


def main() -> None:
    parser = argparse.ArgumentParser(prog='dump redfish api',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--hostname',
                        dest='hostname',
                        help='address of the actual redfish API.',
                        required=False,
                        default=DEFAULT_HOSTNAME)
    parser.add_argument('--port',
                        dest='port',
                        help='port of the actual redfish API.',
                        required=False,
                        default=DEFAULT_PORT)
    parser.add_argument('--username',
                        dest='username',
                        help='username to access the redfish API.',
                        required=False,
                        default=DEFAULT_USERNAME)
    parser.add_argument('--password',
                        dest='password',
                        help='password to access the redfish API.',
                        required=False,
                        default=DEFAULT_PASSWORD)
    parser.add_argument('--output',
                        dest='output',
                        help='the directory where the dump will be written.',
                        required=False,
                        default=DEFAULT_DUMP_DIRECTORY)
    args = parser.parse_args()

    if not os.path.exists(args.output):
        os.makedirs(args.output)
    elif os.path.exists(args.output) and not os.path.isdir(args.output):
        print(f'{args.output} exists but is not a directory. Exiting.')
        raise SystemExit(1)

    try:
        client = RedFishClient(args.hostname,
                               args.port,
                               args.username,
                               args.password)
        client.login()
        root = json.loads(client.query(endpoint='/redfish/v1/')[1])
    except RuntimeError:
        print(f"Can't connect to {args.hostname}")
        raise SystemExit()
    try:
        data = [{k: v} for k, v in root.items() if '@odata.id' in v]
        with ThreadPoolExecutor() as executor:
            executor.map(get_odata_ids, data, repeat(args.output), repeat(client))

    except Exception as e:
        print(e)

    client.logout()


if __name__ == '__main__':
    main()
