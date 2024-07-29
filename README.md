# agda-tree

Converts `*.lagda.tree` to `*.tree`.

## Usage

Let's say you have a forest (evergreen notes system via [forester](https://www.jonmsterling.com/jms-005P.xml)), and the directory structure is

```
.
 |
 |-forest.toml      (config of forester)
 |-trees            (for forester)
 |-xxx
 | |-xxx.agda-lib
```

then you can run

```sh
agda-tree build xxx
```
After that, you can move generated `*.tree` to `trees/` directory in forest, then you can view literate Agda in forster system. The current internal working flow is as follows:

![image](https://github.com/dannypsnl/agda-tree/blob/main/workflow.svg)

This will change if agda directly accept `*.lagda.tree` as input, at that case I will update agda-tree to fit it.

## Example

![image](https://github.com/user-attachments/assets/ea6412f2-b53b-479a-9307-5934ac5804fd)
