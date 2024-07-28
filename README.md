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

The command will

1. compile `*.lagda.tree` in `xxx/` to `*.lagda.md`
2. generates a `index.agda` that import `*`, so this is a proper root module.
3. invoke `agda --html index.agda`
4. read `*.html` to generate `*.tree`

After that, you can move generated `*.tree` to `trees/` directory in forest, then you can view literate Agda in forster system.

## Example

![image](https://github.com/user-attachments/assets/ea6412f2-b53b-479a-9307-5934ac5804fd)
