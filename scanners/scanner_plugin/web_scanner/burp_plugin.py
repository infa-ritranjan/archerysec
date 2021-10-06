# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime

from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import HttpResponse
from notifications.signals import notify
from PyBurprestapi import burpscanner

from archerysettings.models import BurpSettingDb, EmailDb
from webscanners import email_notification
from webscanners.models import (WebScanResultsDb, WebScansDb,
                                burp_issue_definitions)

to_mail = ""


def email_notify(user, subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        pass


class burp_scans(object):
    """
    Burp Scanner Plugin for Archery.
    """

    project_id = None
    target_url = None
    scan_ip = None
    burp_status = 0
    name = "NA"
    host = "NA"
    path = "NA"
    location = "NA"
    severity = "NA"
    confidence = "NA"
    references = "NA"
    vul_col = "NA"
    false_positive = None
    data = None
    url = "NA"
    request_type = "NA"
    request_datas = "NA"
    response_type = "NA"
    response_datas = "NA"
    was_redirect_followed = "NA"
    issue_remediation = "NA"
    issue_reference = "NA"
    issue_vulnerability_classifications = "NA"

    def __init__(self, project_id, scan_url, scan_id, user, recorded, login_details ):
        """

        :param project_id:
        :param scan_url:
        :param recorded;
        :param login_details;
        :param scan_id:
        :param user:
        """

        self.project_id = project_id
        self.scan_url = scan_url
        self.recorded = recorded
        self.login_details = login_details
        self.scan_id = scan_id
        self.user = user

    def scan_launch(self):
        """
        The function trigger the scans.
        """
        burp_host = None
        burp_port = None
        burp_api_key = None

        global burp_status, data

        # Load setting parameters from BurpSettingDb models
        all_burp_settings = BurpSettingDb.objects.filter()

        for data in all_burp_settings:
            burp_host = data.burp_url
            burp_port = data.burp_port
            burp_api_key = data.burp_api_key

        date_time = datetime.now()
        scan_dump = WebScansDb(
            scan_id=self.scan_id,
            project_id=self.project_id,
            scan_url=self.scan_url,
            date_time=date_time,
            scanner="Burp",
        )
        scan_dump.save()

        host = "http://" + burp_host + ":" + burp_port + "/"
        bi = burpscanner.BurpApi(host, burp_api_key)
        #data = '{"urls":["%s"]}' % self.scan_url
        import json 
        #json_file = open('/home/kali/Downloads/extra-git-installation/archerysec/scanners/scanner_plugin/web_scanner/bwapp.json')
        #recorded_login = json_file.read()
        #son_file.close()
        #print(recorded_login)
        #json_file = json.dumps(recorded_login)
        #val2 = recorded_login
        #val2 ='[\n\
        #{\n\
        #    "name": "Burp Suite Navigation Recorder",\n\
        #   "version": "1.3.5",\n\
        #    "eventType": "start"\n\
        #}\n\
        #]'
        #print(val2)
        #data = '{"application_logins":[{"label":"junji","script":"[     {         \"name\": \"Burp Suite Navigation Recorder\",         \"version\": \"1.3.5\",         \"eventType\": \"start\"     },     {         \"date\": \"2021-09-01T19:58:56.315Z\",         \"timestamp\": 1630526336315,         \"eventType\": \"goto\",         \"url\": \"http://localhost/bWAPP/login.php\",         \"triggersNavigation\": true,         \"fromAddressBar\": true     },     {         \"date\": \"2021-09-01T19:59:03.683Z\",         \"timestamp\": 1630526343683,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d0jq0dei4p9-kas1c38deg-kly476trb3m\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:04.563Z\",         \"timestamp\": 1630526344563,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"3fgxwg5f7su-7wckdph0hm2-505wcqbqsig\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bee\"     },     {         \"date\": \"2021-09-01T19:59:08.722Z\",         \"timestamp\": 1630526348722,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"1wxiz52vumz-jd92q2klqdf-8cwi6rfh3h4\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:09.489Z\",         \"timestamp\": 1630526349489,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"09mwtqaef3c9-adjwq19l63p-cgxltxyovoj\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bui\"     },     {         \"date\": \"2021-09-01T19:59:10.712Z\",         \"timestamp\": 1630526350712,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:10.903Z\",         \"timestamp\": 1630526350903,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.092Z\",         \"timestamp\": 1630526351092,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.286Z\",         \"timestamp\": 1630526351286,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.977Z\",         \"timestamp\": 1630526351977,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d8lj4a22pe5-s0nax3zx0y-rjrs66wr8sa\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bug\"     },     {         \"date\": \"2021-09-01T19:59:15.190Z\",         \"timestamp\": 1630526355190,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"e81uygao8wq-pdj0cegcg1j-kf659q9tm9c\",         \"tagName\": \"BUTTON\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"form\",         \"id\": \"\",         \"textContent\": \"Login\",         \"innerHTML\": \"Login\",         \"value\": \"submit\",         \"elementType\": \"submit\",         \"xPath\": \"/html/body/div[2]/form/button\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:15.232Z\",         \"timestamp\": 1630526355232,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/portal.php\"     },     {         \"date\": \"2021-09-01T19:59:20.425Z\",         \"timestamp\": 1630526360425,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"gzgvkwe5eh7-zeg13wtnsf-fxyzkvvlvqa\",         \"tagName\": \"DIV\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"menu\",         \"textContent\": \"\\n\\n    \\n\\n        \\n\\n            Bugs\\n            Change Password\\n            Create User\\n            S\",         \"innerHTML\": \"\\n\\n    <table>\\n\\n        <tbody><tr>\\n\\n            <td><font color=\\\"#ffb717\\\">Bugs</font></td>\\n         \",         \"xPath\": \"/html/body/div\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.022Z\",         \"timestamp\": 1630526361022,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"hqgvuxxrm5j-i41405kvux-0bzcpmg4fvl\",         \"tagName\": \"A\",         \"eventType\": \"click\",         \"tagNodeIndex\": 2,         \"href\": \"http://localhost/bWAPP/security_level_set.php\",         \"className\": \"\",         \"name\": \"\",         \"id\": \"\",         \"textContent\": \"Set Security Level\",         \"innerHTML\": \"Set Security Level\",         \"elementType\": \"\",         \"xPath\": \"/html/body/div/table/tbody/tr/td[4]/a\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.062Z\",         \"timestamp\": 1630526361062,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/security_level_set.php\"     },     {         \"date\": \"2021-09-01T19:59:25.259Z\",         \"timestamp\": 1630526365259,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"655cqkb9kga-tdcxz7guyxb-e04mm9kfds9\",         \"tagName\": \"HEADER\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"\",         \"textContent\": \"\\n\\nbWAPP\\n\\nan extremely buggy web app !\\n\\n\",         \"innerHTML\": \"\\n\\n<h1>bWAPP</h1>\\n\\n<h2>an extremely buggy web app !</h2>\\n\\n\",         \"xPath\": \"/html/body/header\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     } ]","type":"RecordedLogin"}],"urls":["http://localhost/bWAPP/portal.php"]}'
        #print(self.login_details)
        #data = json.dumps('{"application_logins":[{"label":"junji","script":"%s","type":"RecordedLogin"}], "urls":["%s"]}' %(self.recorded, self.scan_url))
        #data = '{"application_logins":[{"label":"junji","script":"%s","type":"RecordedLogin"}], "urls":["%s"]}' %(self.recorded, self.scan_url)
        #print(data)
        #data = '{"application_logins":[{"password":"bug","type":"UsernameAndPasswordLogin","username":"bee"}],"urls":["%s"]}' % self.scan_url
        #data = '{"application_logins":[{"label":"junji","script":"[     {         \"name\": \"Burp Suite Navigation Recorder\",         \"version\": \"1.3.5\",         \"eventType\": \"start\"     },     {         \"date\": \"2021-09-01T19:58:56.315Z\",         \"timestamp\": 1630526336315,         \"eventType\": \"goto\",         \"url\": \"http://localhost/bWAPP/login.php\",         \"triggersNavigation\": true,         \"fromAddressBar\": true     },     {         \"date\": \"2021-09-01T19:59:03.683Z\",         \"timestamp\": 1630526343683,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d0jq0dei4p9-kas1c38deg-kly476trb3m\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:04.563Z\",         \"timestamp\": 1630526344563,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"3fgxwg5f7su-7wckdph0hm2-505wcqbqsig\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bee\"     },     {         \"date\": \"2021-09-01T19:59:08.722Z\",         \"timestamp\": 1630526348722,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"1wxiz52vumz-jd92q2klqdf-8cwi6rfh3h4\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:09.489Z\",         \"timestamp\": 1630526349489,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"09mwtqaef3c9-adjwq19l63p-cgxltxyovoj\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bui\"     },     {         \"date\": \"2021-09-01T19:59:10.712Z\",         \"timestamp\": 1630526350712,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:10.903Z\",         \"timestamp\": 1630526350903,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.092Z\",         \"timestamp\": 1630526351092,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.286Z\",         \"timestamp\": 1630526351286,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.977Z\",         \"timestamp\": 1630526351977,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d8lj4a22pe5-s0nax3zx0y-rjrs66wr8sa\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bug\"     },     {         \"date\": \"2021-09-01T19:59:15.190Z\",         \"timestamp\": 1630526355190,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"e81uygao8wq-pdj0cegcg1j-kf659q9tm9c\",         \"tagName\": \"BUTTON\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"form\",         \"id\": \"\",         \"textContent\": \"Login\",         \"innerHTML\": \"Login\",         \"value\": \"submit\",         \"elementType\": \"submit\",         \"xPath\": \"/html/body/div[2]/form/button\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:15.232Z\",         \"timestamp\": 1630526355232,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/portal.php\"     },     {         \"date\": \"2021-09-01T19:59:20.425Z\",         \"timestamp\": 1630526360425,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"gzgvkwe5eh7-zeg13wtnsf-fxyzkvvlvqa\",         \"tagName\": \"DIV\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"menu\",         \"textContent\": \"\\n\\n    \\n\\n        \\n\\n            Bugs\\n            Change Password\\n            Create User\\n            S\",         \"innerHTML\": \"\\n\\n    <table>\\n\\n        <tbody><tr>\\n\\n            <td><font color=\\\"#ffb717\\\">Bugs</font></td>\\n         \",         \"xPath\": \"/html/body/div\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.022Z\",         \"timestamp\": 1630526361022,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"hqgvuxxrm5j-i41405kvux-0bzcpmg4fvl\",         \"tagName\": \"A\",         \"eventType\": \"click\",         \"tagNodeIndex\": 2,         \"href\": \"http://localhost/bWAPP/security_level_set.php\",         \"className\": \"\",         \"name\": \"\",         \"id\": \"\",         \"textContent\": \"Set Security Level\",         \"innerHTML\": \"Set Security Level\",         \"elementType\": \"\",         \"xPath\": \"/html/body/div/table/tbody/tr/td[4]/a\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.062Z\",         \"timestamp\": 1630526361062,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/security_level_set.php\"     },     {         \"date\": \"2021-09-01T19:59:25.259Z\",         \"timestamp\": 1630526365259,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"655cqkb9kga-tdcxz7guyxb-e04mm9kfds9\",         \"tagName\": \"HEADER\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"\",         \"textContent\": \"\\n\\nbWAPP\\n\\nan extremely buggy web app !\\n\\n\",         \"innerHTML\": \"\\n\\n<h1>bWAPP</h1>\\n\\n<h2>an extremely buggy web app !</h2>\\n\\n\",         \"xPath\": \"/html/body/header\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     } ]","type":"RecordedLogin"}],"urls":["%s"]}' % self.scan_url
        #data = '{"application_logins":[{"label":"junji","script":"[     {         \"name\": \"Burp Suite Navigation Recorder\",         \"version\": \"1.3.5\",         \"eventType\": \"start\"     },     {         \"date\": \"2021-09-01T19:58:56.315Z\",         \"timestamp\": 1630526336315,         \"eventType\": \"goto\",         \"url\": \"http://localhost/bWAPP/login.php\",         \"triggersNavigation\": true,         \"fromAddressBar\": true     },     {         \"date\": \"2021-09-01T19:59:03.683Z\",         \"timestamp\": 1630526343683,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d0jq0dei4p9-kas1c38deg-kly476trb3m\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:04.563Z\",         \"timestamp\": 1630526344563,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"3fgxwg5f7su-7wckdph0hm2-505wcqbqsig\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"login\",         \"id\": \"login\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"text\",         \"xPath\": \"/html/body/div[2]/form/p/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bee\"     },     {         \"date\": \"2021-09-01T19:59:08.722Z\",         \"timestamp\": 1630526348722,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"1wxiz52vumz-jd92q2klqdf-8cwi6rfh3h4\",         \"tagName\": \"INPUT\",         \"eventType\": \"click\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"characterPos\": 0     },     {         \"date\": \"2021-09-01T19:59:09.489Z\",         \"timestamp\": 1630526349489,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"09mwtqaef3c9-adjwq19l63p-cgxltxyovoj\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bui\"     },     {         \"date\": \"2021-09-01T19:59:10.712Z\",         \"timestamp\": 1630526350712,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:10.903Z\",         \"timestamp\": 1630526350903,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.092Z\",         \"timestamp\": 1630526351092,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.286Z\",         \"timestamp\": 1630526351286,         \"eventType\": \"keyboard\",         \"shiftKey\": false,         \"ctrlKey\": false,         \"altKey\": false,         \"key\": \"Backspace\",         \"charCode\": 0     },     {         \"date\": \"2021-09-01T19:59:11.977Z\",         \"timestamp\": 1630526351977,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"d8lj4a22pe5-s0nax3zx0y-rjrs66wr8sa\",         \"tagName\": \"INPUT\",         \"eventType\": \"typing\",         \"placeholder\": \"\",         \"tagNodeIndex\": 1,         \"className\": \"\",         \"name\": \"password\",         \"id\": \"password\",         \"textContent\": \"\",         \"innerHTML\": \"\",         \"value\": \"\",         \"elementType\": \"password\",         \"xPath\": \"/html/body/div[2]/form/p[2]/input\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false,         \"typedValue\": \"bug\"     },     {         \"date\": \"2021-09-01T19:59:15.190Z\",         \"timestamp\": 1630526355190,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"e81uygao8wq-pdj0cegcg1j-kf659q9tm9c\",         \"tagName\": \"BUTTON\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"name\": \"form\",         \"id\": \"\",         \"textContent\": \"Login\",         \"innerHTML\": \"Login\",         \"value\": \"submit\",         \"elementType\": \"submit\",         \"xPath\": \"/html/body/div[2]/form/button\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:15.232Z\",         \"timestamp\": 1630526355232,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/portal.php\"     },     {         \"date\": \"2021-09-01T19:59:20.425Z\",         \"timestamp\": 1630526360425,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"gzgvkwe5eh7-zeg13wtnsf-fxyzkvvlvqa\",         \"tagName\": \"DIV\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"menu\",         \"textContent\": \"\\n\\n    \\n\\n        \\n\\n            Bugs\\n            Change Password\\n            Create User\\n            S\",         \"innerHTML\": \"\\n\\n    <table>\\n\\n        <tbody><tr>\\n\\n            <td><font color=\\\"#ffb717\\\">Bugs</font></td>\\n         \",         \"xPath\": \"/html/body/div\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.022Z\",         \"timestamp\": 1630526361022,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"hqgvuxxrm5j-i41405kvux-0bzcpmg4fvl\",         \"tagName\": \"A\",         \"eventType\": \"click\",         \"tagNodeIndex\": 2,         \"href\": \"http://localhost/bWAPP/security_level_set.php\",         \"className\": \"\",         \"name\": \"\",         \"id\": \"\",         \"textContent\": \"Set Security Level\",         \"innerHTML\": \"Set Security Level\",         \"elementType\": \"\",         \"xPath\": \"/html/body/div/table/tbody/tr/td[4]/a\",         \"triggersNavigation\": true,         \"triggersWithinDocumentNavigation\": false     },     {         \"date\": \"2021-09-01T19:59:21.062Z\",         \"timestamp\": 1630526361062,         \"eventType\": \"userNavigate\",         \"url\": \"http://localhost/bWAPP/security_level_set.php\"     },     {         \"date\": \"2021-09-01T19:59:25.259Z\",         \"timestamp\": 1630526365259,         \"windowInnerWidth\": 1920,         \"windowInnerHeight\": 833,         \"uniqueElementID\": \"655cqkb9kga-tdcxz7guyxb-e04mm9kfds9\",         \"tagName\": \"HEADER\",         \"eventType\": \"click\",         \"tagNodeIndex\": 0,         \"className\": \"\",         \"id\": \"\",         \"textContent\": \"\\n\\nbWAPP\\n\\nan extremely buggy web app !\\n\\n\",         \"innerHTML\": \"\\n\\n<h1>bWAPP</h1>\\n\\n<h2>an extremely buggy web app !</h2>\\n\\n\",         \"xPath\": \"/html/body/header\",         \"triggersNavigation\": false,         \"triggersWithinDocumentNavigation\": false     } ]","type":"RecordedLogin"}],"urls":["http://localhost/bWAPP/portal.php"]}'
        #print(data)
        #print(' ----- -------- ----- ----- ------ ---')
        #print(data)
        #print(' ===== ===== ===== =-==== ===== ==== ===== ')
        
        if(self.recorded):
            data = '{"application_logins":[{"label":"recorded","script":"%s","type":"RecordedLogin"}], "urls":["%s"]}' %(self.recorded, self.scan_url)
        elif(self.login_details != {} and self.login_details['user'] != '' and self.login_details['pass'] != ''):
            data = '{"application_logins":[{"password":"%s","type":"UsernameAndPasswordLogin","username":"%s"}], "urls":["%s"]}' % (self.login_details['pass'], self.login_details['user'], self.scan_url)
        else:
            data = '{"urls":["%s"]}' % self.scan_url

        response = bi.scan(data)
        scan_data = response.response_headers
        burp_scan_id = scan_data["location"]

        # Email Notification
        message = "Burp Scan Launched "
        subject = "Archery Burp Scan Notification"
        #email_notify(user=self.user, subject=subject, message=message)

        # Dashboard Notification
        notify.send(self.user, recipient=self.user, verb="Burp Scan Launched")

        scan_info = bi.scan_info(burp_scan_id)
        json_scan_data = json.dumps(scan_info.data)
        scan_info_data = json.loads(json_scan_data)
        scan_status = scan_info_data["scan_metrics"]["crawl_and_audit_progress"]
        print(scan_status)

        while int(scan_status) < 100:
            scan_info = bi.scan_info(burp_scan_id)
            json_scan_data = json.dumps(scan_info.data)
            scan_info_data = json.loads(json_scan_data)
            scan_status = scan_info_data["scan_metrics"]["crawl_and_audit_progress"]
            print("Scan Status:", scan_status)
            WebScansDb.objects.filter(scan_id=self.scan_id, scanner="Burp").update(
                scan_status=scan_status
            )
            time.sleep(5)

        scan_info = bi.scan_info(burp_scan_id)
        json_scan_data = json.dumps(scan_info.data)
        scan_info_data = json.loads(json_scan_data)
        scan_data = scan_info_data["issue_events"]
        do_scan_dat = burp_scans(
            self.project_id, self.scan_url, self.scan_id, self.user, self.recorded, self.login_details
        )
        do_scan_dat.burp_scan_data(scan_data)

    def burp_scan_data(self, scan_data):
        """
        The function parse the burp result as xml data
        and stored into archery database.
        :param xml_data:
        :return:
        """
        severity = ""
        type_index = ""
        name = ""
        path = ""
        issue_description = ""
        request_datas = ""
        response_datas = ""
        issue_vulnerability_classifications = ""
        url = ""
        issue_remediation = ""
        issue_reference = ""

        for data in scan_data:
            for key, value in data["issue"].items():
                if key == "name":
                    name = value

                if key == "origin":
                    origin = value

                if key == "confidence":
                    confidence = value

                if key == "evidence":
                    evidence = value
                    if evidence is None:
                        print("Evidence not found")
                    else:
                        try:
                            for e in evidence:
                                for key, value in e.items():
                                    if key == "request_response":
                                        url = value["url"]
                                        was_redirect_followed = value[
                                            "was_redirect_followed"
                                        ]

                                        for request_data in value["request"]:
                                            request_type = request_data["type"]
                                            request_datas = base64.b64decode(
                                                (request_data["data"])
                                            )

                                        for request_data in value["response"]:
                                            response_type = request_data["type"]
                                            response_datas = base64.b64decode(
                                                request_data["data"]
                                            )
                        except Exception as e:
                            print(e)

                if key == "caption":
                    caption = value

                if key == "type_index":
                    type_index = value

                if key == "internal_data":
                    internal_data = value

                if key == "serial_number":
                    serial_number = value

                if key == "path":
                    path = value

                if key == "severity":
                    severity = value

            all_issue_definitions = burp_issue_definitions.objects.filter(
                issue_type_id=type_index
            )
            for def_data in all_issue_definitions:
                issue_description = def_data.description
                issue_remediation = def_data.remediation
                issue_vulnerability_classifications = (
                    def_data.vulnerability_classifications
                )
                issue_reference = def_data.reference

            vul_col = ""
            if severity == "high":
                severity = "High"
                vul_col = "danger"
            elif severity == "medium":
                severity = "Medium"
                vul_col = "warning"
            elif severity == "low":
                severity = "Low"
                vul_col = "info"
            elif severity == "info":
                severity = "Info"
                vul_col = "info"
            else:
                vul_col = "info"

            vuln_id = uuid.uuid4()

            dup_data = name + path + severity
            duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

            match_dup = (
                WebScanResultsDb.objects.filter(dup_hash=duplicate_hash)
                .values("dup_hash")
                .distinct()
            )
            lenth_match = len(match_dup)

            if lenth_match == 1:
                duplicate_vuln = "Yes"
            elif lenth_match == 0:
                duplicate_vuln = "No"
            else:
                duplicate_vuln = "None"

            false_p = WebScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash
            )
            fp_lenth_match = len(false_p)

            details = (
                str(issue_description)
                + str("\n")
                + str(request_datas)
                + str("\n\n")
                + str(response_datas)
                + str("\n\n")
                + str(issue_vulnerability_classifications)
            )
            global false_positive
            if fp_lenth_match == 1:
                false_positive = "Yes"
            elif lenth_match == 0:
                false_positive = "No"
            else:
                false_positive = "No"
            date_time = datetime.now()
            try:
                data_dump = WebScanResultsDb(
                    scan_id=self.scan_id,
                    vuln_id=vuln_id,
                    url=url,
                    title=name,
                    solution=issue_remediation,
                    description=details,
                    reference=issue_reference,
                    project_id=self.project_id,
                    severity_color=vul_col,
                    severity=severity,
                    date_time=date_time,
                    false_positive=false_positive,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    scanner="Burp",
                )
                data_dump.save()
            except Exception as e:
                print(e)
        burp_all_vul = (
            WebScanResultsDb.objects.filter(scan_id=self.scan_id)
            .values("title", "severity")
            .distinct()
        )
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))
        total_info = len(burp_all_vul.filter(severity="Info"))
        total_duplicate = len(burp_all_vul.filter(vuln_duplicate="Yes"))
        WebScansDb.objects.filter(scan_id=self.scan_id, scanner="Burp").update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_duplicate,
        )
        try:
            email_notification.email_notify()
        except Exception as e:
            print(e)
        HttpResponse(status=201)
