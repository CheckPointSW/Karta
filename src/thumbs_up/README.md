```
 /$$$$$$$$ /$$                               /$$                       /$$   /$$          
|__  $$__/| $$                              | $$                      | $$  | $$          
   | $$   | $$$$$$$  /$$   /$$ /$$$$$$/$$$$ | $$$$$$$   /$$$$$$$      | $$  | $$  /$$$$$$ 
   | $$   | $$__  $$| $$  | $$| $$_  $$_  $$| $$__  $$ /$$_____/      | $$  | $$ /$$__  $$
   | $$   | $$  \ $$| $$  | $$| $$ \ $$ \ $$| $$  \ $$|  $$$$$$       | $$  | $$| $$  \ $$
   | $$   | $$  | $$| $$  | $$| $$ | $$ | $$| $$  | $$ \____  $$      | $$  | $$| $$  | $$
   | $$   | $$  | $$|  $$$$$$/| $$ | $$ | $$| $$$$$$$/ /$$$$$$$/      |  $$$$$$/| $$$$$$$/
   |__/   |__/  |__/ \______/ |__/ |__/ |__/|_______/ |_______/        \______/ | $$____/ 
                                                                                | $$      
                                                                                | $$      
                                                                                |__/      
``` 

## Purpose
"Thumbs Up" is an additional mini IDA-plugin that was designed to drastically improve IDA's function analysis. The plugin uses basic Machine-Learning and heuristics in order to learn how IDA identified the different features (functions, fptrs, switch-tables, ARM/Thumbs transitions, etc.). After the learning phase, the plugin analyses the binary again, and uses the knowledge it acquired to improve the initial analysis results.

The matching results that Karta produces after using Thumbs Up are almost identical (~96%) to the results we received after we did a manual function analysis (which took us several man days). As Karta's matching results are highly dependent on the quality of the function analysis, it is highly recommended to use Thumbs Up as a pre-process phase before invoking Karta.

## Additional Reading
https://research.checkpoint.com/thumbs-up-using-machine-learning-to-improve-idas-analysis