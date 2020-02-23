#!python3

import json
import sys
import os
import re
import itertools
from pprint import pprint
import uuid
import mitmproxy.io.tnetstring as tnetstring
import yaml
import click
import urllib

_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$')

BODY_METHODS = 'post put patch'.split()


def guess_type(strvalue):
    '''guesses the parameter type from string value

    if it's a numeric string, guesses number, else guesses string

    returns a tuple of (schema, value), where value is converted to guessed type
    '''
    if strvalue.isdigit():
        return {'type': 'number'}, int(strvalue)
    else:
        return {'type': 'string'}, strvalue

#? What is a Merge Function: 
#?   A merge function is a function that given a list of things
#?   "merges" them in some way, and returns a single thing.
#?   Or in types:
#?       MergeFunction[T] = List[T] -> T
#?   Now, most of the following functions are higher order, and
#?   return a MergeFunction, each of which merges in a different way


def _dict_merge(merger, default_merger=None):
    '''Creates a MergeFunction[dict]. `merger` is either a merger function 
    (used for all keys), or a dictionary of merger functions (with each key
    having a different merger). In the latter case, `default_merger` can
    be used as a fallback for nonexistant keys. 

    The result is a dictionary, where each key is the result of merging values 
    from that key from all input dictionaries (which had that key).
    '''

    if not isinstance(merger, dict):
        default_merger = merger
        merger = {}

    def w(dicts):
        keys = {key for d in dicts for key in d.keys()}
        resp = {}

        for key in keys:
            if not key in merger and default_merger is None:
                raise ValueError('unknown merger for key', key)
            resp[key] = merger.get(key, default_merger)([d[key]
                                                 for d in dicts if key in d])
        return resp

    return w

def _first_merge(items):
    '''A `MergerFunction[T]`, that just returns a first item to be
    merged. Others are ignored.
    
    Useful when values are either expected to be the same, or unmergable/irrelevant.
    '''
    return items[0]

def _pp(x, add=None):
    print('>>', add)
    pprint(x)
    return x


def _selector_merge(selectorfn, merger, default_merger=None):
    '''Returns a MergerFunction[list[T]]. A more universal case of _dict_merge where,
    instead of dict keys, we use a custom selector function `selectorfn`.
    '''
    if not isinstance(merger, dict):
        default_merger = merger
        merger = {}

    def _gb(items, key=None):
        '''groupby that works as expected (like in SQL, not like `uniq` in unix)'''
        return itertools.groupby(sorted(items, key=key), key=key)
    def w(lists):
        return [merger.get(k, default_merger)(list(g)) for k, g in _gb([item for items in lists for item in items], key=selectorfn)]

    return w


def is_parameter(value: str):
    '''returns True if the value looks like a parameter. This is VERY subjective.

    I went with "it's an integer, or it's an UUID" since that's what worked for my task. YMMV.
    '''
    if value.isdigit():
        return True
    if _UUID_RE.match(value):
        return True

    return False


def create_schema_for_value(value):
    """Creates a JSON schema for given value.
    """
    if isinstance(value, str):
        return {'type': 'string'}
    if isinstance(value, (int, float)):
        return {'type': 'number'}
    if isinstance(value, bool):
        return {'type': 'boolean'}
    if value is None:
        return {'type': 'null'}
    if isinstance(value, list):
        if len(value) == 0:
            return {'type': 'array', 'items': {}}
        return {
            'type': 'array',
            'items': schema_merge([create_schema_for_value(v) for v in value])
        }
    if isinstance(value, dict):
        return {
            'type': 'object',
            'properties': {
                k: create_schema_for_value(v) for k, v in value.items()
            },
            # by default, everyting is required
            'required': [k for k in value.keys()]
        }

    raise TypeError('invalid json type', type(value))


def schema_merge(schemas):
    """Merges a list of schemas, and returns the resulting schema
    (their union, algebraicaly speaking). 
    
    Does not support all of JSON-Schema yet, just what the rest of
    the code can produce.
    """

    if not isinstance(schemas, list):
        raise TypeError('expected list')

    if not schemas:
        raise ValueError('expected non-empty list')

    schemas = [ s for s in schemas if s ] # remove empty schema

    if len(schemas) == 1:
        return schemas[0]

    if not schemas:
        # all schemas were empty, so result is empty
        return {}

    res = {}
    # print('-----')
    # pprint(schemas)
    types = {s['type'] for s in schemas}

    if 'null' in types:
        # remove all nulls, and just keep
        types.remove('null')
        res['nullable'] = True
        schemas = [s for s in schemas if s['type'] != 'null']

    if len(types) == 0:
        # we only had a null
        return { 'nullable': True }

    if len(types) > 1:
        # multiple types, need 'anyOf'

        res['anyOf'] = [schema_merge(
            [s for s in schemas if s['type'] == t]) for t in types]
        return res

    # only one type, switch on it
    theType = next(iter(types))
    res['type'] = theType
    if theType in ['string', 'number', 'boolean']:
        # primitive types, no need for any merging
        # TODO: support per-type options
        return res

    if theType == 'array':
        # the result is an array, with the
        # 'items' being a merge of all sub-types
        res['items'] = schema_merge([items['items'] for items in schemas])
        return res

    if theType == 'object':
        res['properties'] = {}

        sprops = [s['properties'] for s in schemas]

        allProps = [prop for sp in sprops for prop in sp.keys()]

        res['properties'] = {
            prop: schema_merge([sp[prop] for sp in sprops if prop in sp]) for prop in allProps
        }

        return res


def url_to_params(url: str):
    """Finds potential parameters in URL (things that look like parameters
    according to `is_parameter`), and replaces them with `{templates}`.
    
    Returns:
    -  a tuple `(url, params)` where `url` is the resulting url with templates, 
       and `params` is OpenAPI Parameter Object array of those parameters.

    Parameters are dumbly named `param0`, `param1`, ... which may or may not
    improve in the future.
    """
    # find potential parameter in URL (remove first empty part)
    urlParts = url.split('/')[1:]

    resultUrl = []
    params = []
    i = 0

    for part in urlParts:
        if is_parameter(part):
            resultUrl.append('{param' + str(i) + '}')
            sch, value = guess_type(part)
            value = urllib.parse.unquote(value)
            params.append({
                'name': 'param' + str(i),
                'in': 'path',
                'required': True,
                'schema': sch,
                'example': value
            })
            i += 1
        else:
            resultUrl.append(part)

    url = '/' + '/'.join(resultUrl)

    return url, params


def jsonify(content: str, mimeType: str):
    """Given some content as a string, and it's mime type, tries to parse it
    and convert it to JSON-equivalent shape, to be used in OpenAPI schemas.
    """
    mimeType = mimeType.split(';', 1)[0]

    # try JSON just in case :)
    try:
        return json.loads(content), 'application/json'
    except:
        pass
    if mimeType == 'application/x-www-form-urlencoded':
        pts = content.split('&')
        return {k: v for k, v in (pt.split('=', 1) for pt in pts)}, mimeType

    return content, mimeType  # fallback - raw

_NON_BASE_URL = set()

def path_item_create(flow, hostbase):
    """Creates an OpenAPI Path Item Object for a single request.

    Parameters:
    - `flow` a single flow in MitmProxy format
    - `hostbase` a hase url for API, which will be removed from request URL.

    Returns:
    - `None` if the request is not under `hostbase`
    - (url, path_item) tuple otherwise, where `url` is the URL of the item
      (with the URL parameters filled in), and 

    Of course, it will contain a single method, a single response code, and
    possibly only a part of the schema, but more will be added by merging them
    later on.
    """
    req = flow['request']
    resp = flow['response']
    url: str = req['host'] + req['path']

    if url.startswith(hostbase + '/'):
        url = url[len(hostbase):]
    else:
        num_slash = hostbase.count('/')
        nonBaseUrl = '/'.join(url.split('/')[:num_slash+1])
        if nonBaseUrl not in _NON_BASE_URL:
            _NON_BASE_URL.add(nonBaseUrl)
            print('Non-base URL detected:', nonBaseUrl)
        return None

    if '?' in url:
        url, query_params = url.split('?', 1)
    else:
        query_params = None

    url, params = url_to_params(url)

    def get_header(headers, name, default):
        name = name.lower()
        return next((h[1] for h in headers if h[0].lower() == name), default)

    method = req['method'].lower()

    request_content = req['content']
    request_content_type = get_header(
        req['headers'], 'Content-Type', 'text/plain').split(';')[0]

    if method in BODY_METHODS:
        request_parsed, request_content_type = jsonify(
            request_content, request_content_type)

    response_content = resp['content']
    response_content_type = get_header(
        resp['headers'], 'Content-Type', 'text/plain').split(';')[0]

    response_parsed, response_content_type = jsonify(
        response_content, response_content_type)

    resp_code = resp['status_code']

    def create_content(content_type, parsed):
        return {
            content_type: {
                'schema': create_schema_for_value(parsed),
                'example': parsed
            }
        }

    result = {
        method: {
            'responses': {
                str(resp_code): {
                    'description': resp['reason'],
                    'content': create_content(response_content_type, response_parsed)
                }
            }
        }
    }

    if params:
        result['parameters'] = params

    if method in BODY_METHODS:
        result[method]['requestBody'] = {
            'content': create_content(request_content_type, request_parsed)
        }

    if query_params:
        qpl = []
        for qparam in query_params.split('&'):
            if '=' in qparam:
                name, value = qparam.split('=', 1)
            else:
                name, value = qparam, ''
            name = urllib.parse.unquote(name)
            value = urllib.parse.unquote(value)
            sch, value = guess_type(value)
            r = {
                'name': name,
                'in': 'query',
                'schema': sch,
                'example': value
            }

            qpl.append(r)
        result[method]['parameters'] = qpl

    return url, result


def parameters_merge(parameters):
    '''A MergeFunction[list[ParameterObject]]. Merges lists of OpenAPI Parameter Objects.

    A parameter is distinguished by it's `in` and `name` properties.
    '''
    def selector(parameter):
        return parameter['in'] + ':' + parameter['name']

    x = _selector_merge(selector, _dict_merge({
        'in': _first_merge,
        'name': _first_merge,
        'schema': schema_merge,
        'example': _first_merge
    }))(parameters)

    return x

# merges OpenAPI 'Media Type Object's
media_type_object_merge = _dict_merge({
    'schema': schema_merge,
    'example': _first_merge
})

# merges OpenAPI 'Request Body Object's
request_body_merge = _dict_merge({
    'description': _first_merge,
    'content': _dict_merge(media_type_object_merge)
})


# merger OpenAPI 'Operation Object's
operation_merge = _dict_merge({
    'parameters': parameters_merge,
    'responses': _dict_merge(
        _dict_merge({
            'description': _first_merge,
            'content': _dict_merge(media_type_object_merge)
        })
    ),
    'requestBody': request_body_merge
})

# merges OpenAPI 'Path Item Object's
path_item_merge = _dict_merge({
    'parameters': _first_merge
}, default_merger=operation_merge)


def openapi_create(flows, host):
    '''Creates OpenAPI spec from given flows.

    Parameters:
    - `flows`: HTTP flows (requests/responses) in MitmProxy format.
    - `host`: base host to use. All requests to other hosts will be ignored.

    Returns:
    - a OpenAPI v3.0 spec, as a python dictionary, that can be serialized
      to JSON or YAML
    '''
    rezx = []

    for i, flow in enumerate(flows):
        pi = path_item_create(flow, host)
        if not pi:
            continue

        rezx.append({pi[0]: pi[1]})

    result = _dict_merge(path_item_merge)(rezx)

    oapi = {
        'openapi': '3.0.2',
        'servers': [{
            'url': host
        }],
        'info': {
            'title': 'A Generated OpenAPI Spec',
            'version': '0.0.1'
        },
        'paths': result
    }

    return oapi



def debinarize(x):
    '''Given a JSON-like structure which contains some `bytes` objects,
    removes the `bytes` objects by decoding them. If that fails, just convers
    them to empty strings, since they are probably binary data anyway.
    '''
    if isinstance(x, bytes):
        try:
            return x.decode()
        except:
            return ''

    if isinstance(x, list):
        return [debinarize(y) for y in x]

    if isinstance(x, dict):
        return {
            k: debinarize(v) for k, v in x.items()
        }

    return x

@click.command()
@click.argument('infile')
@click.argument('outfile')
@click.argument('baseurl')
def main(infile, outfile, baseurl):
    '''Convert the given flows from INFILE into a OpenAPI spec and save to OUTFILE,
    that is similar to the API the flows were capturing. BASEURL is the base url of the
    API that you were capturing and is used for documentation and filtering.
    '''
    flows = []

    with open(infile, 'rb') as f:
        f.seek(0, os.SEEK_END)
        n = f.tell()
        f.seek(0, os.SEEK_SET)
        while f.tell() < n:
            flows.append(tnetstring.load(f))

    flows = debinarize(flows)

    oapi = openapi_create(flows, baseurl)

    with open(outfile, 'w') as f:
        yaml.dump(oapi, f, indent=2)

if __name__ == "__main__":
    main()
