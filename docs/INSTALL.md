# Installation
git clone https://github.com/jasonmull/ChainsawMCP.git
cd ChainsawMCP
pip install -e .

# Add MCP Server to Claude
Navigate into your case directory first — this anchors all generated artifacts automatically:

```bash
cd /cases/FINDEVL
claude mcp add ChainsawMCP -- python -m chainsawmcp.server
```

# MCP Server Use
Once in Claude Code, the process can be started with a simple prompt, such as **Run a hunt on all .E01 files in this directory."**  This process kicks off the following process:
 - Validation of Chainsaw and Sigma Ruleset installation.  If these items are not down, the Claude will prompt the user to pull both down from Github.
 - Once prerequisites are validated, the Chainsaw Hunt process begins.  Depending on the size and number of images, this process can be lengthy.  A monitor will be created within Claude to track the Chainsaw Hunt process and enable the analysis process to continue once the Chainsaw Hunt process is complete.
 - Once the Chainsaw Hunt process is complete, the analyst will be presented with high level analysis of  high-risk findings.  The analyst can pull generated reports from the `/cases/<CASE>/reports` directory, or ask Claude further questions about the dataset.
