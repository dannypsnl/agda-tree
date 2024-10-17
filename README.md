# agda-tree

Converts `*.lagda.tree` to `*.tree`.

## Install

```sh
cargo install agda-tree
```

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

![image](https://github.com/user-attachments/assets/7c729e53-71fe-4c3b-9874-700238ffc655)

agda will accept `*.lagda.tree` as input once 2.8.0 release, agda-tree will need to change workflow for that.

## Example

![image](https://github.com/user-attachments/assets/ea6412f2-b53b-479a-9307-5934ac5804fd)
