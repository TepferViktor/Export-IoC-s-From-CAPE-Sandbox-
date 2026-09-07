# CAPE IOC Export Module for TI integration

A custom module for **CAPE Sandbox** that extracts and exports **Indicators of Compromise (IOCs)** from analysis results.  
Supports **JSON**, **CSV**, and **STIX 2.1** export formats, with a user-friendly web interface integrated into the CAPE web UI.

---

## Features

- **IOC Extraction**: Automatically collects IOCs from:
  - **Signatures** (including embedded `iocs` and `data` fields)
  - **Network traffic** (hosts, TCP/UDP connections)
  - **DNS queries and answers**
  - **Files** (extracted, dropped, and target file hashes)
  - **VirusTotal** data (if available)
- **Export Formats**:
  - **JSON** – raw structured data
  - **CSV** – tabular format for spreadsheets
  - **STIX 2.0** – standardized threat intelligence format (optional)
- **Web Interface**:
  - List of all analyses with their status
  - Detailed IOC view per task
  - One-click download in any supported format
- **MongoDB Integration** – reads directly from the CAPE database.

---

## Prerequisites

- **CAPE Sandbox** (v2 or later) installed and running
- Python 3.6+ with Django
- MongoDB (the same database used by CAPE)
- `stix2` Python library (optional, for STIX export)

---

## Installation

### 1. Copy the Module Files

Place the provided files into the CAPE web directory structure:

| Source File                     | Destination Path                         |
|---------------------------------|------------------------------------------|
| `views_ioc.py`                  | `/opt/CAPEv2/web/web/views_ioc.py`       |
| `export_ioc_list.html`          | `/opt/CAPEv2/web/templates/export_ioc_list.html` |
| `export_ioc_page.html`          | `/opt/CAPEv2/web/templates/export_ioc_page.html` |

```bash
cp views_ioc.py /opt/CAPEv2/web/web/
cp export_ioc_list.html /opt/CAPEv2/web/templates/
cp export_ioc_page.html /opt/CAPEv2/web/templates/
```

---

### 2. Update URL Routes

Edit `/opt/CAPEv2/web/web/urls.py` and add the following:

```python
from . import views_ioc   # at the top of the file
```

Inside the `urlpatterns` list, add:

```python
path('ioc/export/', views_ioc.export_ioc_list, name='export_ioc_list'),
path('ioc/export/<int:task_id>/', views_ioc.export_ioc_page, name='export_ioc_page'),
path('ioc/export/<int:task_id>/download/<str:format>/', views_ioc.download_ioc, name='download_ioc'),
```

> **Note:** If your CAPE uses **string `ObjectId`** for task IDs (e.g., MongoDB `_id`), change `<int:task_id>` to `<str:task_id>` in all three patterns.

---

### 3. Add Navigation Menu Item

Edit `/opt/CAPEv2/web/templates/header.html`.  
Find the `<ul class="navbar-nav">` block and insert:

```html
<li class="nav-item {% if request.resolver_match.url_name in 'export_ioc_list export_ioc_page' %}active{% endif %}">
    <a class="nav-link" href="{% url 'export_ioc_list' %}">
        <i class="fas fa-file-export"></i> Export IOC
    </a>
</li>
```

This adds a new menu entry to the CAPE web interface.

---

### 4. Install Optional Dependencies

For **STIX 2.0** export, install the `stix2` library:

```bash
cd /opt/CAPEv2/web
poetry add stix2
```

If you skip this step, JSON and CSV exports will still work.

---

### 5. Restart the Web Service

Apply the changes by restarting the CAPE web service:

```bash
sudo systemctl restart cape-web.service
```

---

## Usage

### Access the Export Page

1. Open your CAPE web interface.
2. Click on the new **“Export IOC”** menu item in the top navigation bar.

You will see a list of all analyses with columns:
- **ID** – analysis ID
- **Target** – filename or URL
- **Added** – start time
- **Status** – Success / Failed / unknown
- **Action** – “View IOC” button

### View and Export IOCs

- Click **“View IOC”** on any analysis row.
- The detailed IOC page shows:
  - Total number of IOCs found
  - A table with columns: **Type**, **Value**, **Description**, **Source**
  - **Download** buttons for JSON, CSV, and (if installed) STIX 2.0

- Click any download button to save the IOCs in the chosen format.

---

## Output Formats

### JSON
A simple list of objects with fields:
```json
[
  {
    "type": "ipv4-addr",
    "value": "192.168.1.1",
    "description": "Network host",
    "source": "Network"
  },
  ...
]
```

### CSV
A plain-text table with the same fields, suitable for Excel or other spreadsheet tools.

### STIX 2.1
A structured JSON bundle conforming to the STIX 2.1 standard.  
It includes:
- **Identity** (CAPE Sandbox as the producer)
- **Indicators** for each IOC (with appropriate pattern)
- **Grouping** objects (grouped by source)
- **Report** bundling all objects

The STIX export requires the `stix2` library and will gracefully skip any IOC without a defined STIX pattern.

---

## Customization

- **IOC Collection Logic**: Edit `collect_iocs()` in `views_ioc.py` to add new data sources or modify extraction rules.
- **STIX Mapping**: Adjust the pattern generation for different IOC types inside the `download_ioc` view.
- **UI Styling**: The templates can be customised to match your CAPE theme.

---

## Troubleshooting

### “Analysis not found” error
- Ensure the task ID exists in your CAPE MongoDB database.
- If you are using string ObjectIds, update the URL patterns as described in step 2.

### STIX export fails
- Check that `stix2` is installed (`poetry add stix2`).
- Ensure your Python environment has the necessary dependencies.

### Missing IOCs
- Verify that the analysis actually contains network, file, or signature data.
- Check the MongoDB structure – the module expects the standard CAPE document schema.

### Web service not reflecting changes
- After editing files, restart the web service:
  ```bash
  sudo systemctl restart cape-web.service
  ```
- Clear your browser cache if the menu item doesn't appear.

---

## License

This module is provided under the same license as CAPE Sandbox (GPLv3).  
See the CAPE project for details.

---

## Credits

Developed as a custom extension for CAPE Sandbox.  
For questions or contributions, please refer to the CAPE community.

---

**Happy Threat Hunting!** 🦠🔍
