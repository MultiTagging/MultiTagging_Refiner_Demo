# MultiTagging
A vulnerable Ethereum smart contract labeling framework.
## Features
The MultiTagging framework provides several functions through the following components:
*  **Tagger:** It parses analysis tool reports to extract vulnerability tags and map them to the common vulnerability labels, i.e., SWC codes and DASP Ranks.
*  **Evaluator:** It measures the performance of the tool using different evaluation metrics.
*  **Elector:** It elects the sample label based on votes of a number of tools. It supports three voting options: AtLeastOne, Majority, and Threshold.
*  **Plotter:** It plots the evaluation results in different formats.
## Supported Tools
* The components of the MultiTagging framework can be utilized for any analysis tool except for the Tagger.
* Currently Tagger supports 6 tools: MAIAN, Mythril, Semgrep, Slither, Solhint, and VeriSmart.
## Requirements
*  <A Href="https://www.python.org/">Python</A> >=3.11.7
*  You can run MultiTagging frame work using <A Href="https://jupyter.org/"> Jupyter Notebook</A> or from <A Href="https://support.apple.com/en-sa/guide/terminal/apd5265185d-f365-44cb-8b09-71a064a42125/mac">Terminal</A>.
## Usage
1.   Clone <A Href="https://github.com/shikahJS/MultiTagging/tree/main"> MultiTagging repository </A>
   ```
      git clone https://github.com/shikahJS/MultiTagging.git
   ```
2.   Go to the MultiTagging home directory.
   ```
      cd MutliTagging
   ```
3.   Replace files in <A Href="https://github.com/shikahJS/MultiTagging/tree/main/ToolReports">ToolReports</A>, <A Href="https://github.com/shikahJS/MultiTagging/tree/main/ToolAnalysisTime">ToolAnalysisTime</A>, and <A Href="https://github.com/shikahJS/MultiTagging/tree/main/BaseDS">BaseDS</A> with your study's files. You can alternatively update the <A Href="https://github.com/shikahJS/MultiTagging/blob/main/Scripts/config.json"> Scripts/config.json </A> file.
4.   Run MutliTagging framework, there are three options:
      1. **Termianl Option:**
         1.   Run <A Href="https://github.com/shikahJS/MultiTagging/blob/main/Main.py">Main.py</A> to open the wizard program. 
         ```
         python3 Main.py
         ```
         2.   Pass your choises and enter the requested input to get the output.
         ```
         MultiTagging Framework
         ..................................................
         
         Enter the number of the selected function:
          1: Get the labeled data for the tool reports.
          2: Get vote-based labeled data. 
          3: Get the evaluation report.
          4: Get the evaluation chart.
          5: Get tools overlap degree.
          6: Exit
         ..................................................
         ```
         3.   Check the <A Href="https://github.com/shikahJS/MultiTagging/tree/06153cf181ad723e61420d5480c5f319ef4aaafe/Results">Results</A> directory to get the saved output.
      2. **Jupyter Notebook:**
         * In a code cell, Run <A Href="https://github.com/shikahJS/MultiTagging/blob/main/Main.py">Main.py</A> to open the wizard program. 
      ```
      run -i 'Main.py'
      ```
      3. **Within your Python code**
        *   You can call any function of MultiTagging framework directly. Check the <A Href="https://github.com/shikahJS/MultiTagging/blob/main/MultiTagging.ipynb">Multhitagging framework demo</A>
## Demo
*  The Multhitagging framework demo is available here: <A Href="https://github.com/shikahJS/MultiTagging/blob/main/MultiTagging.ipynb">MultiTagging.ipynb</A>
*  For the Demo's output: check the <A Href="https://github.com/shikahJS/MultiTagging/tree/06153cf181ad723e61420d5480c5f319ef4aaafe/Results">Results</A> directory.
