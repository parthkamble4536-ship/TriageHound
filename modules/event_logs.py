from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

# Key Event IDs to look for
INTERESTING_EVENTS = {
    4624: "Successful Login",
    4625: "Failed Login",
    4720: "User Account Created",
    6416: "New External Device Recognized (USB)",
    1000: "Application Crash"
}

def parse_evtx(evtx_path):
    events = []
    try:
        with Evtx(evtx_path) as log:
            for record in log.records():
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                event_id_elem = root.find('.//ns:EventID', ns)
                time_elem = root.find('.//ns:TimeCreated', ns)

                if event_id_elem is not None:
                    event_id = int(event_id_elem.text)
                    if event_id in INTERESTING_EVENTS:
                        events.append({
                            'event_id': event_id,
                            'description': INTERESTING_EVENTS[event_id],
                            'timestamp': time_elem.get('SystemTime') if time_elem is not None else None
                        })
    except Exception as e:
        pass
        
    return events
