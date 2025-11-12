## ✅ 使用场景举例

假设你有一个「合约操作延迟系统」：
管理员要修改重要参数（比如升级合约），必须等一段时间（比如 7 天）才能执行，防止立刻更改带来风险。

### 📍 最开始的情况

- 当前延迟：7 天
- 还没有预约更新

所以：

```ini
valueBefore = 7 天
valueAfter =*0
effectTimepoint = 0
```

👉 意思是：“现在延迟是 7 天，没有预约修改”。

### 📅 管理员想修改延迟

有一天，管理员觉得「7 天太久了」，想改成「1 天」。
但系统不能立刻让他改为 1 天 —— 因为这太危险了。
所以规定：

> “如果要减少延迟时间，必须再等一段时间后才生效。”

假设规则是:

- 最小等待时间（minSetback）= 2 天
- 当前延迟 = 7 天
- 新延迟 = 1 天
- 当前时间 = 100 （假设是时间戳）
  那计算规则是：

```typescript
setback = max(minSetback, valueBefore - valueAfter)
        = max(2, 7 -1)
        = 6 天
```

于是新的生效时间点：

```typescript
effectTimepoint = 100 + 6 天
```

于是打包：

```typescript
valueBefore = 7 天     （现在还是旧的）
valueAfter  = 1 天     （新值）
effectTimepoint = 当前时间 + 6 天
```

📍 生效前
此时系统里的状态（Delay）是：
| 参数 | 值 | 含义 |
| --------------- | --------- | --------- |
| valueBefore | 7 天 | 当前延迟 |
| valueAfter | 1 天 | 计划改成的延迟 |
| effectTimepoint | 100 + 6 天 | 改成新延迟的时间点 |

📍 生效时间到了
时间过了 6 天，到达 effectTimepoint。
系统再看 Delay 的状态时，发现：

```typescript
if (effectTimepoint <= block.timestamp)
    => 当前时间 >= 未来生效时间
```

于是自动切换成：
| 参数 | 值 | 含义 |
| --------------- | --- | ---------- |
| valueBefore | 1 天 | 新值已经成为当前延迟 |
| valueAfter | 0 | 没有下一个预约 |
| effectTimepoint | 0 | 清空预约 |

👉 意思就是：“延迟已经更新为 1 天，预约完成”。

---

## ✅ 单例误区

### 🧩 一、关键结论

> Time.Delay 是一种类型（type），
> 它不保存任何具体的值，
> 每个合约、甚至每个变量，都可以有自己独立的 Delay 值。

所以：

- ❌ 它不是全局单例。
- ✅ 它是一个“值类型”（value type），像 uint、bool 一样，谁用谁有自己的一份。

### 🧠 二、举例说明

```solidity
contract A {
    Time.Delay public delayA;
}

contract B {
    Time.Delay public delayB;
}

```

- A 合约里有自己的一个延迟值；
- B 合约里也有自己的延迟值；
- 两个变量互不影响。

它们只是使用同一个类型定义，但每个变量的数据都存在各自的存储槽（storage slot）中。

## ✅ max(minSetback, ...)解析

### withUpdate 函数

```solidity
function withUpdate(
    Delay self,
    uint32 newValue,
    uint32 minSetback
) internal view returns (Delay updatedDelay, uint48 effect) {
    uint32 value = self.get(); // 当前延迟值
    uint32 setback = uint32(Math.max(
        minSetback,
        value > newValue ? value - newValue : 0
    ));
    effect = timestamp() + setback;
    return (pack(value, newValue, effect), effect);
}
```

### 它的任务是：

> 当用户（通常是管理员）要修改延迟值时，
> 生成一个新的 “延迟对象（Delay）”，
> 并指定一个未来生效的时间（effectTimepoint）。

### minSetback 是一个 底线等待时间。

它保证：

> 无论你怎么改延迟，都必须至少等这么久之后才能生效。

### 为什么还要比较 (valueBefore - valueAfter)？

> “valueBefore - valueAfter” 表示你想提前的天数，
> 系统强制让你再等那么久，
> 保证没有任何操作能比旧规则规定的等待时间更早执行。

🔁 例子重现（通俗版）
| 场景 | 计算 | 意思 |
| ----------- | ----------------------------- | -------------------- |
| 从 7 天 改成 1 天 | `setback = max(2, 7-1) = 6` | 因为你想提前 6 天，所以要多等 6 天 |
| 从 1 天 改成 7 天 | `setback = max(2, 0) = 2` | 加大延迟没风险，只等最少 2 天即可 |
| 从 3 天 改成 2 天 | `setback = max(2, 3-2) = 2` | 想提前 1 天，但系统最低要等 2 天 |
| 从 10 天 改成 0 天 | `setback = max(2, 10-0) = 10` | 想完全取消延迟，要等 10 天后才行 |

## ✅ 位操作
```yaml
| effect (48 bits) | valueBefore (32 bits) | valueAfter (32 bits) |
 ↑ 高位                                           低位 ↑
```
索引区间（从右往左数）：
| 区间     | 含义          |
| ------ | ----------- |
| 0–31   | valueAfter  |
| 32–63  | valueBefore |
| 64–111 | effect      |

### 取出每一段的方式

<span style="color:yellow">①取低 32 位（valueAfter）</span>
直接：
```solidity
valueAfter = uint32(raw);
```
👉 把高位全部丢弃，只保留最后 32 位。


<span style="color:yellow">② 取中间的 32 位（valueBefore）</span>

要先把高 64 位右移掉，再取最低的 32 位：
```solidity
valueBefore = uint32(raw >> 32);
```
📘 比喻：
想拿第二段，就要“先右移掉第一段（valueAfter）”。
因为右移 32 位后：
```yaml
[effect:48][valueBefore:32][valueAfter:32] >> 32
= [effect:48][valueBefore:32]
```
然后再强制转成 uint32（只保留最后 32 位），就得到了 valueBefore。


<span style="color:yellow">③ 取高 48 位（effect）</span>

再右移 64 位（32 + 32）：
```solidity
effect = uint48(raw >> 64);
```
右移 64 位后，只剩下高 48 位（effect），
再强转成 uint48，得到结果。

### 打包的反向操作（<< 左移）

与 >> 相反，在 pack() 里用的是左移：
```solidity
(uint112(effect) << 64) | (uint112(valueBefore) << 32) | uint112(valueAfter);
```
表示：
- 把 effect 往左移 64 位（放到最高处）
- 把 valueBefore 往左移 32 位（放中间）
- 把 valueAfter 保持不动（留在最低位）
- 然后用 |（按位或）把三段“拼在一起”
