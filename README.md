In this Repository, I have completed the Day 20 Async programming - Promise Task

==> Task-1 ( VirusTotal Scanner )

I have built a web-based application that allows users to scan URLs and files for viruses and malware using  HTML, DOM, CSS, Bootstrap, Advanced Javascript and VirusTotal API.

=> Technical Details

    * I used VirusTotal API to inspect items with over 70 antivirus scanners and URL/domain blocklisting services.
        * VirusTotal API - www.virustotal.com/api/v3/
    * I have used Fetch API to make HTTP requests to the VirusTotal API.
    * Also used various endpoints to get those scanned details
         * www.virustotal.com/api/v3/files
         * www.virustotal.com/api/v3/urls
         * www.virustotal.com/api/v3/analyses/${fileId}
         * www.virustotal.com/api/v3/widget/url?query=${sha256}
    * I have used Promise to handle the asynchronous nature of the Fetch API.
    * I have used the DOM to display the scan results on the page.
    * This page is also Responsive on all screens

=> Features

 * Scan URLs and files for viruses and malware.
 * Display detailed reports from VirusTotal

==> This page is also Deployed on Netlify URL: https://ryd-vtscanner.netlify.app
