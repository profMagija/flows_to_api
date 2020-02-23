# `flows_to_api` - HTTP API reverse engineering utility

Converts HTTP flows (sniffed HTTP trafic) into OpenAPI documentation.
Useful for reverse engineering HTTP APIs.

## Usage

0. Turn `mitmproxy` on, and route your traffic through it.
1. Excercise the app you are reverse engineering. Try to trigger as much of the API as possible, with as much possible combinations of arguments.
2. Save the flows from mitmproxy by typing `w` and specifying the filename. There is no need to filter the flows, as `flows_to_api` will filter the requests.
3. Know your `baseurl` - this is the base of the API you are reverse engineering, and is at least the full hostname, eg `api.example.com`. You can also specify a subpath, eg `www.example.com/api`. Note that there is no trailing slash!
    - if API you are sniffing is made of multiple endpoints, you will need to run the script for each one, generating one OpenAPI doc for each.
4. Invoke the script:
```
./flows_to_api.py <input file> <output yaml file> <baseurl>
```
eg
```
./flows_to_api.py saved_flows.txt output_file.yaml api.example.com
```
5. Open the output file in your favourite OpenAPI previewer, or use it to generate mocks / stubs.