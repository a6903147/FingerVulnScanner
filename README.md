# FingerVulnScanner

**FingerVulnScanner** 是一个根据目标系统指纹进行专项漏洞扫描的工具，旨在大量资产里快速取得外网权限。该工具使用 CMS 对应的 POC 进行扫描，减少误报并且减小对目标系统的压力。

## 工作流程

1. 先对所有资产的指纹进行搜集，
2. 再根据目标指纹获取漏洞库里对应的 POC，
3. 最后根据与资产相对应的 POC 进行漏洞扫描。

## 支持参数

- `-u` 对单个目标进行扫描
- `-f` 对多个目标进行扫描

## 示例

```bash
python FingerVulnScanner.py -f url.txt
```
![image](https://github.com/user-attachments/assets/77d12e48-8f19-4ad3-a358-eaeee68032aa)

## 项目基于

- [POC-bomber](https://github.com/tr0uble-mAker/POC-bomber)
- [chunsou](https://github.com/Funsiooo/chunsou)
- [EHole](https://github.com/EdgeSecurityTeam/EHole)
