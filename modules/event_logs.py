"""
Windows Event Log Parser (Enhanced)
=====================================
Parses .evtx files and extracts ALL event fields, not just a hardcoded
list of Event IDs. This enables the Sigma Rules Engine to match against
any field in any event.
"""

from Evtx.Evtx import Evtx  # pyrefly: ignore[missing-import]
import xml.etree.ElementTree as ET

# Key Event IDs for quick filtering (original functionality)
INTERESTING_EVENTS = {
    4624: "Successful Login",
    4625: "Failed Login",
    4720: "User Account Created",
    4698: "Scheduled Task Created",
    4732: "User Added to Privileged Group",
    7045: "New Service Installed",
    1102: "Security Event Log Cleared",
    6416: "New External Device Recognized (USB)",
    1000: "Application Crash",
}


def parse_evtx(evtx_path, extract_all=False):
    """
    Parse a Windows Event Log (.evtx) file.

    Args:
        evtx_path: Path to the .evtx file
        extract_all: If True, extract ALL events with full field data
                     (needed for Sigma rule matching).
                     If False, only extract events with interesting Event IDs.

    Returns:
        list of event dicts
    """
    events = []
    try:
        with Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)

                    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                    # Extract core System fields
                    event_id_elem = root.find('.//ns:EventID', ns)
                    time_elem = root.find('.//ns:TimeCreated', ns)
                    provider_elem = root.find('.//ns:Provider', ns)
                    computer_elem = root.find('.//ns:Computer', ns)
                    channel_elem = root.find('.//ns:Channel', ns)

                    if event_id_elem is None:
                        continue

                    event_id = int(event_id_elem.text)
                    timestamp = time_elem.get('SystemTime') if time_elem is not None else None

                    # If not extracting all, only keep interesting events
                    if not extract_all and event_id not in INTERESTING_EVENTS:
                        continue

                    event = {
                        'event_id': event_id,
                        'EventID': event_id,
                        'timestamp': timestamp,
                        'description': INTERESTING_EVENTS.get(event_id, f'Event {event_id}'),
                        'provider': provider_elem.get('Name', '') if provider_elem is not None else '',
                        'computer': computer_elem.text if computer_elem is not None else '',
                        'channel': channel_elem.text if channel_elem is not None else '',
                    }

                    # Extract EventData fields (key-value pairs)
                    event_data = root.find('.//ns:EventData', ns)
                    if event_data is not None:
                        for data_elem in event_data:
                            name = data_elem.get('Name', '')
                            value = data_elem.text or ''
                            if name:
                                event[name] = value

                    # Extract UserData fields (alternate format)
                    user_data = root.find('.//ns:UserData', ns)
                    if user_data is not None:
                        for child in user_data:
                            for data_elem in child:
                                tag = data_elem.tag.split('}')[-1] if '}' in data_elem.tag else data_elem.tag
                                if data_elem.text:
                                    event[tag] = data_elem.text

                    events.append(event)

                except (ET.ParseError, ValueError, AttributeError):
                    continue

    except Exception:
        pass

    return events
