# Dataset Details
MCP Server testing was performed against the "SRL 2018 - Compromised Enterprise Network" dataset provided as part of the SANS FINDEVIL AI Hackathon.  A sample report can be found in this repository under `docs/DataSetOutput`.  THis sample reporting is based on the analysis of two forensic images within the dataset, **base-rd-01-cdrive.E01** and **base-rd-02-cdrive.E01**.  Specifically, the following sample outputs are provided.
 - **hunt_reports.zip** - A zipped output of the Chainsaw hunt analysis process.  This file is Chainsaw-only output which has ben modified to add a `hit_id` value to each record.  This value is used to match LLM analysis to documented Chainsaw findings.
 - **hunt_report.txt** - A text-based output from ChainsawMCP that groupd all Chainsaw rule hits
 - **FINDEVIL_comprehensive_report.md** - An LLM-enriched incident report based on Chainsaw output.  FOr esch of the findings in this report, specific Chainsaw records are mapped by `hit_id`.
