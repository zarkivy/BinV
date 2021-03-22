```
__________.__     ____   ____
\______   \__| ___\   \ /   /
 |    |  _/  |/    \   Y   /
 |    |   \  |   |  \     /
 |______  /__|___|  /\___/
        \/        \/
```

> 来自车间流水线的二进制漏洞扫描器
>
> Yet another binary vulnerbilities checker



## Introduction

- 这个项目是我在北京理工大学的本科毕业设计。试着基于**符号执行**，实现针对于 ELF 的自动化漏洞扫描器。
- 基于 **[Angr 9.0](https://github.com/angr/angr)** 实现，于近期持续开发中。
- This project is my undergraduate graduation project in Beijing Institute of Technology. Try to implement an automated vulnerability scanner for ELF based on **symbolic execution**.
- Implemented based on **[Angr 9.0](https://github.com/angr/angr)**, continues to be developed recently.



## Schedule

- 目前已实现对于 **stack overflow(draft)、format string bug(draft)、double free、use after free(with some bugs)** 漏洞类型的检测功能。
- 实现了简单的路径优化与剪枝策略，提升了检测效率，减少了对于重复路径的误报。
- 正在撰写论文初稿，同时试图找到预先静态分析的优化方案。
- Currently, the detection for **stack overflow(draft)、format string bug(draft)、double free、use after free(with some bugs)** vulnerability types have been implemented.
- A simple path optimization and pruning strategy is implemented, which improves detection efficiency and reduces false alarms for repeated paths.
- The first draft of the paper is being written, and at the same time, I am trying to find an optimal solution for pre-static analysis.



## Temporary demo

![demo](https://raw.githubusercontent.com/IZAY01/BinV/main/docs/img/demo.png)
