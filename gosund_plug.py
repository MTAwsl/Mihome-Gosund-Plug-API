from miio import MiioSession
import json

class GosundPlug(MiioSession):
    def __init__(self, ip, token):
        super().__init__(ip, bytes.fromhex(token))
    def status(self) -> bool:
        stat = json.loads(self.send(b"{\"id\": 1, \"method\": \"get_prop\", \"params\": [{\"did\": \"state\", \"siid\": 2, \"piid\": 1}]}").decode())
        return stat['result'][0]['value']
    def on(self) -> None:
        self.send(b"{\"id\": 1, \"method\": \"set_properties\", \"params\": [{\"did\": \"state\", \"siid\": 2, \"piid\": 1, \"value\": true}]}")
        return
    def off(self) -> None:
        self.send(b"{\"id\": 1, \"method\": \"set_properties\", \"params\": [{\"did\": \"state\", \"siid\": 2, \"piid\": 1, \"value\": false}]}")
        return