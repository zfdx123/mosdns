# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)


# 自用修改

## 修改的插件

### auto_reload

- 支持自动重载 auto_reload

```yaml
plugins:
  - tag: domain_set
    type: domain_set
    args:
      auto_reload: true
      debounce_time: 5 # 防抖时间，防止一次性写入太多数据导致未写入完成读取
      files:
        - /path/to/domain_set.txt
  - tag: ip_set
    type: ip_set
    args:
      auto_reload: true
      debounce_time: 5 # 防抖时间，防止一次性写入太多数据导致未写入完成读取
      files:
        - /path/to/ip_set.txt
  - tag: hosts
    type: hosts
    args:
      auto_reload: true
      debounce_time: 5 # 防抖时间，防止一次性写入太多数据导致未写入完成读取
      files:
        - /path/to/hosts.txt
```

## 新增插件

### NGTIP
联动微步NGTIP或云API实现恶意域名或域名返回恶意IP封禁

#### 推荐 API
```api
# cloud
https://api.threatbook.cn/v3/scene/dns # 支持IP和域名

#情报网关
http://ip:8090/tip_api/v5/dns 似乎查不到ip所以我们单独使用IP接口查询
http://ip:8090/tip_api/v5/ip ip单独查询
```

```yaml
plugins:
  - tag: "intel_block_domain"
    type: intel_block_domain
    args:
      # api: http://ip:8090/tip_api/v5/dns
      api: https://api.threatbook.cn/v3/scene/dns
      key: # APIKEY
      is_cloud: true
      timeout: 5000 # http 超时 5000ms
      cache_ttl: 86400 # 缓存过期 
      whitelist_file: "./user/while.yaml" # 白名单 跳过检查
      reload_interval: 5 # 修改文件后多久重新加载文件进行防抖

  - tag: "intel_block_ip"
    type: intel_block_ip
    args:
      # api: http://ip:8090/tip_api/v5/ip
      api: https://api.threatbook.cn/v3/scene/dns
      key: # APIKEY
      is_cloud: true
      timeout: 5000
      cache_ttl: 86400
      whitelist_file: "./user/while.yaml"
      reload_interval: 5
      
  - tag: main_entry
    type: sequence
    args:
      - exec: prefer_ipv4

      # 屏蔽恶意域名
      - matches:
          - qname $blacklist
          - qname $geosite_category-ads-all
        exec: reject 3

      # 静态解析
      - exec: $hosts
      - exec: jump has_resp_sequence

      # 域名级情报，查询阶段
      - exec: $intel_block_domain
      - exec: jump has_resp_sequence

      # DNS 缓存
      - exec: $dns_cacher
      - exec: jump has_resp_sequence
        
      ## 你的原来的逻辑

      - exec: $intel_block_ip
      - exec: jump has_resp_sequence

```

### collect

域名收集插件，用于收集和管理DNS查询中的域名，支持添加和删除操作，具有高性能缓存机制。

#### 核心特性

- **双向操作**：支持域名的添加和删除操作
- **三种格式**：
  - `domain`：域名格式 `domain:example.com`
  - `full`：完整格式 `full:example.com` 
  - `keyword`：关键词格式 `keyword:example.com`
- **高性能架构**：
  - 启动时加载文件内容到内存缓存
  - 添加操作：内存检查去重 + 异步追加写入
  - 删除操作：内存立即删除 + 异步文件重写
- **数据一致性**：
  - 多实例共享机制，同文件只有一个实例
  - 异步写入队列，容量1000，带重试机制
  - 临时文件+原子重命名，确保文件操作安全
- **自动热加载**：配合 `domain_set` 插件实现文件变化自动重载

#### 配置参数

```yaml
plugins:
  - tag: domain_collector
    type: collect
    args:
      format: full                    # 域名格式：domain/full/keyword，默认full
      file_path: /path/to/domains.txt # 文件路径（必填）
      operation: add                  # 操作类型：add/delete，默认add
```