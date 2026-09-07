from django.shortcuts import render, get_object_or_404, Http404
from django.http import HttpResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.conf import settings
from bson import ObjectId
import json
import csv
from django.utils import timezone
import pymongo
from stix2 import Bundle, Indicator, Identity, Report, Grouping

def get_mongo_db():
    client = pymongo.MongoClient(
        host=settings.MONGO_HOST,
        port=settings.MONGO_PORT,
        username=settings.MONGO_USER,
        password=settings.MONGO_PASS,
        authSource=settings.MONGO_AUTHSOURCE,
    )
    return client[settings.MONGO_DB]

@staff_member_required
def export_ioc_list(request):
    db = get_mongo_db()
    tasks = db.analysis.find().sort("_id", -1)
    return render(request, 'export_ioc_list.html', {'tasks': tasks, 'title': 'Export IOC'})

@staff_member_required
def export_ioc_page(request, task_id):
    db = get_mongo_db()
    task = None
    if ObjectId.is_valid(task_id):
        task = db.analysis.find_one({"_id": ObjectId(task_id)})
    if not task:
        try:
            task = db.analysis.find_one({"info.id": int(task_id)})
        except ValueError:
            pass
    if not task:
        raise Http404("Analysis not found")
    iocs = collect_iocs(task, db)
    return render(request, 'export_ioc_page.html', {
        'task': task,
        'iocs': iocs,
        'title': f'IOC Export #{task.get("info", {}).get("id", task_id)}'
    })

def extract_hashes(obj, db=None):
    result = {}
    if not obj:
        return result
    for htype in ['sha256', 'md5', 'ssdeep', 'sha1']:
        if htype in obj and obj[htype]:
            result[htype] = obj[htype]
    if 'virustotal' in obj and isinstance(obj['virustotal'], dict):
        vt = obj['virustotal']
        for htype in ['sha256', 'md5', 'ssdeep', 'sha1']:
            if htype in vt and vt[htype] and htype not in result:
                result[htype] = vt[htype]
    if 'file_ref' in obj and obj['file_ref'] and db is not None:
        try:
            file_doc = db.files.find_one({"sha256": obj['file_ref']})
            if file_doc:
                for htype in ['sha256', 'md5', 'ssdeep', 'sha1']:
                    if htype in file_doc and file_doc[htype] and htype not in result:
                        result[htype] = file_doc[htype]
        except:
            pass
    return result

def collect_iocs(task, db=None):
    iocs = []

    if "signatures" in task and task["signatures"]:
        for sig in task["signatures"]:
            if "data" in sig and sig["data"]:
                for item in sig["data"]:
                    if isinstance(item, dict):
                        ioc_type = item.get("type") or item.get("ioc_type")
                        value = item.get("value") or item.get("ioc")
                        if value:
                            iocs.append({
                                'type': ioc_type or "unknown",
                                'value': value,
                                'description': sig.get("description", sig.get("name", "")),
                                'source': f"Signature: {sig.get('name', '')}"
                            })
                    elif isinstance(item, str):
                        iocs.append({
                            'type': "unknown",
                            'value': item,
                            'description': sig.get("description", sig.get("name", "")),
                            'source': f"Signature: {sig.get('name', '')}"
                        })
            if "iocs" in sig and sig["iocs"]:
                for ioc in sig["iocs"]:
                    if isinstance(ioc, dict):
                        iocs.append({
                            'type': ioc.get('type', 'unknown'),
                            'value': ioc.get('value'),
                            'description': sig.get("description", sig.get("name", "")),
                            'source': f"Signature: {sig.get('name', '')}"
                        })

    if "network" in task and task["network"]:
        net = task["network"]
        if "hosts" in net and net["hosts"]:
            for host in net["hosts"]:
                iocs.append({
                    'type': 'ipv4-addr' if ':' not in host else 'ipv6-addr',
                    'value': host,
                    'description': 'Network host',
                    'source': 'Network'
                })
        for proto in ["tcp", "udp"]:
            if proto in net and net[proto]:
                for conn in net[proto]:
                    if "dst" in conn and "ip" in conn["dst"]:
                        ip = conn["dst"]["ip"]
                        port = conn["dst"].get("port")
                        desc = f"Connection to {ip}" + (f":{port}" if port else "")
                        iocs.append({
                            'type': 'ipv4-addr' if ':' not in ip else 'ipv6-addr',
                            'value': ip,
                            'description': desc,
                            'source': f'Network ({proto.upper()})'
                        })

    if "dns" in task and task["dns"]:
        for dns in task["dns"]:
            if "request" in dns and dns["request"]:
                iocs.append({
                    'type': 'domain',
                    'value': dns['request'],
                    'description': f"DNS query to {dns['request']}",
                    'source': 'DNS'
                })
            if "answer" in dns and dns["answer"]:
                answers = dns["answer"] if isinstance(dns["answer"], list) else [dns["answer"]]
                for ans in answers:
                    iocs.append({
                        'type': 'ipv4-addr' if ':' not in ans else 'ipv6-addr',
                        'value': ans,
                        'description': f"DNS resolved to {ans}",
                        'source': 'DNS'
                    })

    for field in ["files", "dropped"]:
        if field in task and task[field]:
            for f in task[field]:
                hashes = extract_hashes(f, db)
                for htype, hvalue in hashes.items():
                    if hvalue and not any(ioc["type"] == htype and ioc["value"] == hvalue for ioc in iocs):
                        iocs.append({
                            'type': htype,
                            'value': hvalue,
                            'description': f.get("name", "Extracted file"),
                            'source': f'File ({field})'
                        })

    if "target" in task and "file" in task["target"]:
        file_info = task["target"]["file"]
        hashes = extract_hashes(file_info, db)
        for htype, hvalue in hashes.items():
            if hvalue and not any(ioc["type"] == htype and ioc["value"] == hvalue for ioc in iocs):
                iocs.append({
                    'type': htype,
                    'value': hvalue,
                    'description': f"Target file hash: {file_info.get('name', 'unknown')}",
                    'source': 'Target file'
                })

    return iocs

def safe_description(desc):
    if isinstance(desc, list):
        return ' '.join(str(item) for item in desc)
    return str(desc) if desc else ''

@staff_member_required
def download_ioc(request, task_id, format):
    db = get_mongo_db()
    task = None
    if ObjectId.is_valid(task_id):
        task = db.analysis.find_one({"_id": ObjectId(task_id)})
    if not task:
        try:
            task = db.analysis.find_one({"info.id": int(task_id)})
        except ValueError:
            pass
    if not task:
        raise Http404("Analysis not found")
    iocs = collect_iocs(task, db)

    if format == 'json':
        response = HttpResponse(json.dumps(iocs, indent=2), content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="iocs_task_{task_id}.json"'
        return response

    elif format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="iocs_task_{task_id}.csv"'
        writer = csv.DictWriter(response, fieldnames=['type', 'value', 'description', 'source'])
        writer.writeheader()
        writer.writerows(iocs)
        return response

    elif format == 'stix2':
        try:
            from uuid import uuid4

            identity = Identity(
                spec_version="2.1",
                name="CAPE Sandbox",
                identity_class="organization",
                created=timezone.now(),
                modified=timezone.now()
            )

            indicators = []
            groups = {}

            for ioc in iocs:
                pattern = None
                ioc_type = ioc['type']
                value = ioc['value']

                if ioc_type == 'ipv4-addr':
                    pattern = f"[ipv4-addr:value = '{value}']"
                elif ioc_type == 'domain':
                    pattern = f"[domain-name:value = '{value}']"
                elif ioc_type == 'sha256':
                    pattern = f"[file:hashes.'SHA-256' = '{value}']"
                elif ioc_type == 'md5':
                    pattern = f"[file:hashes.'MD5' = '{value}']"
                elif ioc_type == 'sha1':
                    pattern = f"[file:hashes.'SHA-1' = '{value}']"
                elif ioc_type == 'url':
                    pattern = f"[url:value = '{value}']"
                else:
                    continue

                if pattern:
                    source_raw = ioc.get('source', 'unknown')
                    if isinstance(source_raw, list):
                        source = '_'.join(str(s) for s in source_raw)
                    else:
                        source = str(source_raw).replace(' ', '_')

                    desc_raw = ioc.get('description', '')
                    desc_clean = safe_description(desc_raw).replace(' ', '_')[:50]

                    desc = f"CAPE_{ioc_type}_{source}_{value}"
                    if desc_clean:
                        desc += f"_{desc_clean}"

                    try:
                        ind = Indicator(
                            spec_version="2.1",
                            pattern=pattern,
                            pattern_type="stix",
                            description=desc,
                            labels=["malicious"],
                            created=timezone.now(),
                            modified=timezone.now(),
                            valid_from=timezone.now(),
                            confidence=60,
                            created_by_ref=identity.id
                        )
                        indicators.append(ind)
                        if source not in groups:
                            groups[source] = []
                        groups[source].append(ind)
                    except Exception:
                        continue

            grouping_objects = []
            for src, inds in groups.items():
                if not inds:
                    continue
                grouping = Grouping(
                    spec_version="2.1",
                    name=f"IOCs from source: {src}",
                    context="ioc",
                    object_refs=[ind.id for ind in inds],
                    created=timezone.now(),
                    modified=timezone.now(),
                    created_by_ref=identity.id
                )
                grouping_objects.append(grouping)

            all_refs = [ind.id for ind in indicators] + [grp.id for grp in grouping_objects]
            report = Report(
                spec_version="2.1",
                name=f"IOCs for CAPE task #{task_id}",
                published=timezone.now(),
                object_refs=all_refs,
                created=timezone.now(),
                modified=timezone.now(),
                labels=["ioc"],
                description="Indicators of compromise extracted from CAPE sandbox analysis",
                created_by_ref=identity.id
            )

            objects = [identity, report] + indicators + grouping_objects
            bundle = Bundle(objects)

            response = HttpResponse(
                bundle.serialize(pretty=True),
                content_type='application/json'
            )
            response['Content-Disposition'] = f'attachment; filename="iocs_task_{task_id}.stix.json"'
            return response

        except ImportError:
            return HttpResponse("STIX library not installed", status=500)
        except Exception as e:
            return HttpResponse(f"STIX generation error: {str(e)}", status=500)

    else:
        return HttpResponse(status=400)
