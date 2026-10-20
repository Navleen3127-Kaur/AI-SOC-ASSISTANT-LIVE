import json
from typing import Any

def get_nested(d: dict, path: str) -> Any:
    if not isinstance(d, dict):
        return None
    parts = path.split('.')
    curr = d
    for part in parts:
        if not isinstance(curr, dict):
            return None
        val = curr.get(part)
        if val is not None:
            curr = val
            continue
        found = False
        for k, v in curr.items():
            if k.lower() == part.lower():
                curr = v
                found = True
                break
        if not found:
            return None
    return curr

def extract_forensic_field(source: dict, paths: list[str], default: str = "Not available") -> Any:
    for path in paths:
        val = get_nested(source, path)
        if val is not None and val != "":
            return val
    return default

def extract_forensics(source: dict) -> dict[str, Any]:
    # Sysmon Event ID
    event_id = extract_forensic_field(source, [
        "data.win.system.eventID",
        "data.win.system.eventid",
        "data.win.eventdata.eventID",
        "data.win.eventdata.eventid",
        "win.system.eventid",
        "data.eventid",
        "eventid"
    ])
    
    # Image
    image = extract_forensic_field(source, [
        "data.win.eventdata.image",
        "win.eventdata.image",
        "data.image",
        "image"
    ])
    
    # Process ID
    process_id = extract_forensic_field(source, [
        "data.win.eventdata.processId",
        "data.win.eventdata.processid",
        "win.eventdata.processid",
        "data.processid",
        "processid"
    ])
    
    # Process GUID
    process_guid = extract_forensic_field(source, [
        "data.win.eventdata.processGuid",
        "data.win.eventdata.processguid",
        "win.eventdata.processguid",
        "data.processguid",
        "processguid"
    ])
    
    # User
    user = extract_forensic_field(source, [
        "data.win.eventdata.user",
        "data.win.eventdata.subjectUserName",
        "win.eventdata.user",
        "data.dstuser",
        "data.user",
        "user"
    ])
    
    # Target Filename
    target_filename = extract_forensic_field(source, [
        "data.win.eventdata.targetFilename",
        "data.win.eventdata.targetfilename",
        "win.eventdata.targetfilename",
        "data.targetfilename",
        "targetfilename"
    ])
    
    # Creation Time
    creation_time = extract_forensic_field(source, [
        "data.win.eventdata.creationUtcTime",
        "data.win.eventdata.creationutctime",
        "win.eventdata.creationutctime",
        "data.creationutctime",
        "creationutctime"
    ])
    
    # Computer
    computer = extract_forensic_field(source, [
        "data.win.system.computer",
        "win.system.computer",
        "data.computer",
        "computer"
    ])
    
    # Command Line
    command_line = extract_forensic_field(source, [
        "data.win.eventdata.commandLine",
        "data.win.eventdata.commandline",
        "win.eventdata.commandline",
        "data.commandline",
        "commandline"
    ])
    
    # Parent Process Image
    parent_image = extract_forensic_field(source, [
        "data.win.eventdata.parentImage",
        "data.win.eventdata.parentimage",
        "win.eventdata.parentimage",
        "data.parentimage",
        "parentimage"
    ])
    
    # Parent Process Command Line
    parent_command_line = extract_forensic_field(source, [
        "data.win.eventdata.parentCommandLine",
        "data.win.eventdata.parentcommandline",
        "win.eventdata.parentcommandline",
        "data.parentcommandline",
        "parentcommandline"
    ])
    
    # Rule elements
    rule_id = extract_forensic_field(source, ["rule.id"], "Not available")
    rule_level = extract_forensic_field(source, ["rule.level"], "Not available")
    rule_description = extract_forensic_field(source, ["rule.description"], "Not available")
    rule_groups = extract_forensic_field(source, ["rule.groups"], "Not available")
    rule_mitre = extract_forensic_field(source, ["rule.mitre"], "Not available")
    
    # Agent elements
    agent_name = extract_forensic_field(source, ["agent.name"], "Not available")
    agent_id = extract_forensic_field(source, ["agent.id"], "Not available")
    agent_ip = extract_forensic_field(source, ["agent.ip"], "Not available")
    
    # Network elements
    source_ip = extract_forensic_field(source, ["data.srcip", "data.src_ip"], "Not available")
    destination_ip = extract_forensic_field(source, ["data.dstip", "data.dst_ip"], "Not available")
    source_port = extract_forensic_field(source, ["data.srcport", "data.src_port"], "Not available")
    destination_port = extract_forensic_field(source, ["data.dstport", "data.dst_port"], "Not available")
    
    # Decoder & Location
    decoder = extract_forensic_field(source, ["decoder.name", "decoder"], "Not available")
    location = extract_forensic_field(source, ["location"], "Not available")
    
    # Timestamp
    timestamp = extract_forensic_field(source, ["timestamp", "@timestamp"], "Not available")
    
    evidence = {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "rule_groups": rule_groups,
        "rule_mitre": rule_mitre,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "sysmon_event_id": event_id,
        "image": image,
        "process_id": process_id,
        "process_guid": process_guid,
        "user": user,
        "target_filename": target_filename,
        "creation_time": creation_time,
        "computer": computer,
        "command_line": command_line,
        "parent_process_image": parent_image,
        "parent_process_command_line": parent_command_line,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "decoder": decoder,
        "location": location,
        "raw_event": source
    }
    return evidence
