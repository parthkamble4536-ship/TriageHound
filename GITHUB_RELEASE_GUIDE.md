# GitHub Publishing & Release Guide

This document contains notes on how to finalize your GitHub repository to make it look professional and how to distribute the tool to users.

## 1. What Screenshots Should I Add?

To make this look like a top-tier project, you should take 4 specific screenshots:

1. **The GUI Running (`gui_main.png`)**: Open the tool by running `python gui.py`. Fill out a dummy Case ID (like "TEST-01") and check a few boxes. Take a screenshot of that clean, dark-themed interface.
2. **The PDF Cover Page (`report_cover.png`)**: Run a test scan and open the generated PDF. Take a screenshot of the front page where it shows the Case ID, Investigator, Target System, and the "Digital Forensics Investigation Report" title.
3. **The PDF Alerts Section (`report_alerts.png`)**: In that same PDF, scroll down to where the red YARA hits or the amber Sigma alerts are shown. A screenshot of those colored warning tables looks extremely professional.
4. **The CLI Output (`cli_output.png`)**: Run the tool in the terminal (like we did earlier with `python main.py --case ...`) and take a screenshot of the clean console output showing the progress steps and the "[!!] MATCH" alerts.

Once you take those, save them in the `screenshots` folder with those exact file names. After that, open your `README.md`, scroll down to line 118, and remove the `<!--` and `-->` tags so the images display!

## 2. Should I "Host" It?

No, you don't "host" a desktop application like you would a website (like Vercel or Netlify). This is a forensic utility, not a web app.

Instead of hosting, you use **GitHub Releases**. Here is exactly what you should do after you push the code to GitHub:

1. On your GitHub repository page, look on the right side for the word **"Releases"** and click **"Create a new release"**.
2. Set the tag version to **v1.0.0**.
3. Give it a title like: **"TriageHound v1.0.0 - Initial Release"**.
4. In the description, just copy-paste the "Quick Start" section from the README.
5. **The most important part:** At the bottom where it says "Attach binaries by dropping them here", upload your `DF_Toolkit.exe` file (from the `dist/` folder) and your `requirements.txt`.

By doing this, anyone visiting your GitHub can just click the "Releases" tab, download the `.exe`, and plug it into a USB drive to try it out immediately without needing to clone the code or install Python! This is exactly how professional open-source security tools (like BloodHound or Mimikatz) are distributed.
