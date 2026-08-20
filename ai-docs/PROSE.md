# Rules for writing prose
This section explains the general rules that should be applied when writing any kind of prose; including, but not limited to GitHub issues, code comments, markdown files and communication with the prompter.

## Rules
- Whenever possible when write using prose use the Simplified Technical English (STE) rules according to the [STE](#ste) section.
- Specifically when writing code comments follow the rules in the [code comment](#code-comments) section.

## Code comments
- Do not write inline code comments for trivial code; for example do not write a code comment about a single function call.
- Add in-line comments to code segments that are not obvious; e.g. nested lambdas with filters. 
- Do not write code comments to document your changes, documentation of your changes should be given directly to the prompter. For example, avoid sentences like "function A no longer does X, so we apply function Y first". 
- Avoid excessive function signatures; functions should typically be so conceptually simple that their function can be described in a few sentences. 
- If function A makes a call to function B, then avoid adding documentation about the internals of function B in function A. 
- Keep comments concise, but not at the cost of readiblity.
- Only edit existing comments if it is actually needed. If they are already correct and fulfilling, then do not edit them. 

## STE
- Use the approved words only as the part of speech and meaning given in the dictionary.
- Make instructions as clear and specific as possible.
- Do not write multi-word nouns that have more than three words.
- Use the approved forms of the verb to make only:
    - The infinitive form
    - The imperative form
    - The simple present tense
    - The simple past tense
    - The simple future tense
    - The past participle (only as an adjective)
- Do not use auxiliary verbs to make complex verb constructions.
- Use the "-ing" form of a verb only as a technical noun or as a modifier in a technical noun.
- Use the active voice. In descriptive writing, one should use the passive voice only when the agent is unknown.
- Write short sentences: no more than 20 words in instructions (procedures) and 25 words in descriptive texts.
- Do not omit parts of the sentence (e.g. verb, subject, article) to make the text shorter.
- Use vertical lists for complex text.
- Write one instruction per sentence.
- Write only one topic per paragraph.
- Do not write more than six sentences in each paragraph.
- Start safety instructions with a clear command or condition.