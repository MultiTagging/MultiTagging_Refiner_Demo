# MultiTagging
A vulnerable Ethereum smart contract labeling framework.
## Features
The MultiTagging framework provides several functions through the following components:
*  **Tagger:** It parses analysis tool reports to extract vulnerability tags and map them to the common vulnerability labels, i.e., SWC codes and DASP Ranks.
*  **Evaluator:** It measures the performance of the tool using different evaluation metrics.
*  **Elector:** It elects the sample label based on vots of a number of tools. It supports three voting options: AtLeastOne, Majority, and Threshold.
*  **Plotter:** It plots the evaluation results in defferent formats.
## Supported Tools
* The components of the MultiTagging framework can be utilized for any analysis tool except for the Tagger.
* Currently Tagger supports 6 tools are: MAIAN, Mythril, Semgrep, Slither, Solhint, and VeriSmart.
## Demo
*  The Multhitagging framework demo is available here: <A Href="https://github.com/shikahJS/MultiTagging/blob/main/MultiTagging.ipynb">MultiTagging.ipynb</A>
