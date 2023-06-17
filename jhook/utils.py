import json

def parseJson(data, decode=True, default=None):
    try:
        if (decode):
            return json.loads(data.decode("utf-8"))
        else:
            return json.loads(data)
    except:
        return default