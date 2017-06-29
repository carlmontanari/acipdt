# acitool

## Updates/News

The latest updates to the master branch represent a MASSIVE overhaul to this tool. The biggest update is the conversion to rendering json files with Jinja2 as oposed to the clunky multi-line strings previously used. There have also been a ton of minor updates/tweaks/bug fixes. Finally the "main.py" (which really needs to be renamed) has been cleaned up a bit and now prompts for directory to the deployment spreadsheet, the IP for the fabric (IP only for now, but could easily enough add name support I believe), and the username and password.

*Note* The multipod functionality is super super super beta! You've been warned.

## Synopsis

ACIPDT - or ACI Power Deployment Tool - is a Python library that is intended to be used for network engineers deploying an ACI fabric. ACIPDT is very much early alpha, later releases should add additional features/functionality as well as optimization and improved error handling. 

## Overview

The "SDN" (hate the term, but it applies) movement has brought a great deal of discussion to the idea of how a network engineer deploys networking equipment. Historically text files, or perhaps macros in Excel have been used as templates for new deployments, and good old-fashioned copy/paste has been the actual deployment vehicle. Among other things, SDN is attempting to change this. With SDN we (networking folk) have been given APIs! However, most network engineers, myself included, have no idea what to do with said APIs.

Cisco ACI, as with the other newtorky "SDN products," in the market have provided some nifty tools in order to begin the journey into this API driven next-generation network world, but the bar to entry in any meaningful way is still rather high. In example, ACI provides an API inspector, which displays the XML or JSON payloads that are configuring the ACI fabric, however the payload on its own of course doesn't do much for a network guy - where am I supposed to paste that into? What became clear to me is that Postman was the obvious answer. Postman is a great tool for getting started with an API, and I have used it extensively with ACI, even to the point of deploying an entire fabric in 2 minutes with a handful of Postman collections. However...

Postman left much to be desired. I'm fairly certain that the way in which I was using it was never really the intended use case. In order to keep the collections to a reasonable size, which in turn kept spreadsheets relatively organized (spreadsheets contained the data to insert as a variable in the payloads), but then I had nine collections to run, which meant nine spreadsheets. On top of all of that, there was very little feedback in terms of even simple success/fail per post -- and even if you captured that output, there would be things that would fail no matter what due to the way the spreadsheet was piping in variables (perhaps more on that later, maybe its just how I was using it).

The result of this frustration is the ACIPDT. My intention is to re-create the functionality that I have used Postman for in Python. In doing so, the goal is to have a single spreadsheet (source of data, could be anything, but a spreadsheet is easy), to run a single script, and to have valuable feedback about the success or failure of each and every POST. ACIPDT itself is not a script that will configure your ACI fabric, but is instead a library that will generate ReST calls that will configure the most common deployment scenarios. In addition to the library itself, I have created a very simple script to ingest a spreadsheet that contains the actual configuration data and pass the data to the appropriate method in the library.

Key features:
- Have a library that is de-coupled from any deployment type of script.
	- This was a goal after early attempts became very intertwined and I was unable to cleanly separate the simple ReST call/payload from the rest of the script.
- Run one script that references one source of data.
	- This is more relevant to the run script than it is to the library, but it was taken into consideration when creating the library. A single spreadsheet (with multiple tabs) is used to house all data, is parsed in the run script, then data is passed as kwargs to the appropriate methods for deployment.
- Have discreet configuration items.
	- Ensure that an Interface Profile on an L3 Out can be modified without deleting/re-creating the parent object. While this library/script is intended for deployments where this is likely not a big deal, it was at any rate a design goal.
- Capture the status of every single call.
	- Each method returns a status code. The run script simply enters this data into the Excel spreadsheet at the appropriate line so you know which POSTs failed and which ones succeeded. This is a simplistic status check, but is leaps better than I was getting with Postman.

## Resources

I believe the code to be relatively straight-forward (and I am very not good at Python), and have provided comments ahead of every method in the library to document what is acceptable to pass to the method. As this is really just a pet project on the weekends, that's probably about it from a resources perspective. Feel free to tweet at me (@carl_niger) if you run into any issues or have a burning desire for a feature add.

## Getting Started

This code is entirely written and supported in Python 3 only. The easiest way to get started is to have Python 3 and PIP3 installed and simply install it as follows:

pip3 install git+https://github.com/carlniger/acitool

## Disclaimer

This is NOT fancy code. It is probably not even "good" code. It does work (for me at least!) though. You can seriously mess up your ACI fabric with this utility if you don't know what you're doing. I take no responsibility for that :)
