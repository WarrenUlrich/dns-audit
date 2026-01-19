import requests
import xml.etree.ElementTree as ET
import urllib3

# Suppress SSL warnings since verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# XML payload
data = """<?xml version="1.0"?>
<PLATXML>
    <header></header>
    <body>
        <data_block>
            <protocol>Plat</protocol>
            <object>addusr</object>
            <action>SQL</action>
            <username>portal</username>
            <password>EyScyM74</password>
            <logintype>staff</logintype>
            <parameters>
                <query>
                    SELECT domain, d_custid, crid
                    FROM domain_dns
                    WHERE (d_active='Y' or d_active='H')
                </query>
            </parameters>
            <properties>
            </properties>
        </data_block>
    </body>
</PLATXML>
"""

url = "https://10.125.1.126:5566/"
headers = {
    "Content-Type": "application/xml"
}

try:
    response = requests.post(
        url,
        data=data,
        headers=headers,
        verify=False,   # equivalent to CURLOPT_SSL_VERIFYPEER = FALSE
        timeout=30
    )

    print(response.status_code)

    response.raise_for_status()

    # Parse XML response
    root = ET.fromstring(response.text)

    # Equivalent to: $response->body->data_block->attributes->data_block
    body = root.find("body")
    data_block = body.find("data_block")
    attributes = data_block.find("attributes")

    if attributes is not None:
        blocks = attributes.findall("data_block")

        for block in blocks:
            bill = {child.tag: child.text for child in block}
            print(bill)
    else:
        print("No attributes/data_block found in response")

except requests.exceptions.RequestException as e:
    print("Error")
    print(e)
except ET.ParseError as e:
    print("Failed to parse XML response")
    print(e)
