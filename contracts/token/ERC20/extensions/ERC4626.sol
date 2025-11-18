// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (token/ERC20/extensions/ERC4626.sol)

pragma solidity ^0.8.24;

import {IERC20, IERC20Metadata, ERC20} from "../ERC20.sol";
import {SafeERC20} from "../utils/SafeERC20.sol";
import {IERC4626} from "../../../interfaces/IERC4626.sol";
import {LowLevelCall} from "../../../utils/LowLevelCall.sol";
import {Memory} from "../../../utils/Memory.sol";
import {Math} from "../../../utils/math/Math.sol";

/**
 * @dev Implementation of the ERC-4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[ERC-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC-20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}, {mint}, {redeem} and {burn} workflows. This contract extends
 * the ERC-20 standard. Any additional extensions included along it would affect the "shares" token represented by this
 * contract and not the "assets" token which is an independent contract.
 *
 * [CAUTION]
 * ====
 * In empty (or nearly empty) ERC-4626 vaults, deposits are at high risk of being stolen through frontrunning
 * with a "donation" to the vault that inflates the price of a share. This is variously known as a donation or inflation
 * attack and is essentially a problem of slippage. Vault deployers can protect against this attack by making an initial
 * deposit of a non-trivial amount of the asset, such that price manipulation becomes infeasible. Withdrawals may
 * similarly be affected by slippage. Users can protect against this attack as well as unexpected slippage in general by
 * verifying the amount received is as expected, using a wrapper that performs these checks such as
 * https://github.com/fei-protocol/ERC4626#erc4626router-and-base[ERC4626Router].
 *
 * Since v4.9, this implementation introduces configurable virtual assets and shares to help developers mitigate that risk.
 * The `_decimalsOffset()` corresponds to an offset in the decimal representation between the underlying asset's decimals
 * and the vault decimals. This offset also determines the rate of virtual shares to virtual assets in the vault, which
 * itself determines the initial exchange rate. While not fully preventing the attack, analysis shows that the default
 * offset (0) makes it non-profitable even if an attacker is able to capture value from multiple user deposits, as a result
 * of the value being captured by the virtual shares (out of the attacker's donation) matching the attacker's expected gains.
 * With a larger offset, the attack becomes orders of magnitude more expensive than it is profitable. More details about the
 * underlying math can be found xref:ROOT:erc4626.adoc#inflation-attack[here].
 *
 * The drawback of this approach is that the virtual shares do capture (a very small) part of the value being accrued
 * to the vault. Also, if the vault experiences losses, the users try to exit the vault, the virtual shares and assets
 * will cause the first user to exit to experience reduced losses in detriment to the last users that will experience
 * bigger losses. Developers willing to revert back to the pre-v4.9 behavior just need to override the
 * `_convertToShares` and `_convertToAssets` functions.
 *
 * To learn more, check out our xref:ROOT:erc4626.adoc[ERC-4626 guide].
 * ====
 *
 * [NOTE]
 * ====
 * When overriding this contract, some elements must be considered:
 *
 * * When overriding the behavior of the deposit or withdraw mechanisms, it is recommended to override the internal
 * functions. Overriding {_deposit} automatically affects both {deposit} and {mint}. Similarly, overriding {_withdraw}
 * automatically affects both {withdraw} and {redeem}. Overall it is not recommended to override the public facing
 * functions since that could lead to inconsistent behaviors between the {deposit} and {mint} or between {withdraw} and
 * {redeem}, which is documented to have lead to loss of funds.
 *
 * * Overrides to the deposit or withdraw mechanism must be reflected in the preview functions as well.
 *
 * * {maxWithdraw} depends on {maxRedeem}. Therefore, overriding {maxRedeem} only is enough. On the other hand,
 * overriding {maxWithdraw} only would have no effect on {maxRedeem}, and could create an inconsistency between the two
 * functions.
 *
 * * If {previewRedeem} is overridden to revert, {maxWithdraw} must be overridden as necessary to ensure it
 * always return successfully.
 * ====
 *
 * Vault 自己的 Shares(相当于自己存的balance)
 *   - ERC4626 继承自 ERC20，所以它有自己的：_balances[owner] // 每个用户持有多少、shares,_totalSupply // 所有 shares 总量
 *   - Shares（份额）代表：用户拥有 vault 中资产的“占比”。
 *   - 用户每存一次钱（deposit），Vault 就 mint 一些 shares 给他。
 *   - 用户每取一次钱（withdraw），Vault 就 burn 一些 shares。
 *   - ❗ ERC4626._balances
 *       存的是 shares（Vault 的份额），不是现实资产。
 *
 * 底层资产资产 _asset
 *   -  _asset._balances[address(this)]  // Vault 里存了多少底层资产、_asset._balances[user] // 用户钱包里多少资产
 *   - ❗ _asset._balances
 *       存的是 真实 Token（USDC/WETH 等），Vault 的 totalAssets 就是这里来的。
 *   -  如果底层资产使用 USDT，那就把 USDT 合约实例赋值给 _asset；
 *      如果底层资产使用 USDC，就把 USDC 合约实例赋值给 _asset。
 *
 * 合约示例：
 *  “使用 USDT 作为底层资产，我 deposit 100 USDT，就是
 *      - _asset._balances[我] -= 100
 *      - _asset._balances[vault] += 100
 *      - ERC4626._balances[我] += shares
 *
 *      用户                          VAULT(金库)
 *      ┌──────────────┐          ┌──────────────────────┐
 *      │ USDT balance │───100──▶ │ USDT balance         │  (真实资产)
 *      └──────────────┘          └──────────────────────┘
 *                                       │
 *                                       │ mint shares
 *                                       ▼
 *                                ┌──────────────────────┐
 *                                │ Shares balance       │  (你的份额, ERC20)
 *                                └──────────────────────┘
 *
 *
 */
abstract contract ERC4626 is ERC20, IERC4626 {
    using Math for uint256;

    // Vault 里面存放的底层资产 Token 地址
    IERC20 private immutable _asset;
    uint8 private immutable _underlyingDecimals;

    /**
     * @dev Attempted to deposit more assets than the max amount for `receiver`.
     */
    error ERC4626ExceededMaxDeposit(address receiver, uint256 assets, uint256 max);

    /**
     * @dev Attempted to mint more shares than the max amount for `receiver`.
     */
    error ERC4626ExceededMaxMint(address receiver, uint256 shares, uint256 max);

    /**
     * @dev Attempted to withdraw more assets than the max amount for `receiver`.
     */
    error ERC4626ExceededMaxWithdraw(address owner, uint256 assets, uint256 max);

    /**
     * @dev Attempted to redeem more shares than the max amount for `receiver`.
     */
    error ERC4626ExceededMaxRedeem(address owner, uint256 shares, uint256 max);

    /**
     * @dev Set the underlying asset contract. This must be an ERC20-compatible contract (ERC-20 or ERC-777).
     */
    constructor(IERC20 asset_) {
        (bool success, uint8 assetDecimals) = _tryGetAssetDecimals(asset_);
        _underlyingDecimals = success ? assetDecimals : 18;
        _asset = asset_;
    }

    /**
     * @dev Attempts to fetch the asset decimals. A return value of false indicates that the attempt failed in some way.
     *  作用：尝试读取资产 token（asset_）的 decimals()。 如果读取失败，则返回 (false, 0)。
     */
    function _tryGetAssetDecimals(IERC20 asset_) private view returns (bool ok, uint8 assetDecimals) {
        // 读取当前solidity自由内存指针的位置
        Memory.Pointer ptr = Memory.getFreeMemoryPointer();

        // 安全地调用 asset_.decimals(),并把返回的前 32 bytes（ABI 编码后的 uint256）取出来做解析。
        (bool success, bytes32 returnedDecimals, ) = LowLevelCall.staticcallReturn64Bytes(
            address(asset_),
            abi.encodeCall(IERC20Metadata.decimals, ())
        );

        // 恢复 free memory pointer，避免内存污染。
        Memory.setFreeMemoryPointer(ptr);

        // success: 调用必须成功，否则说明 token 不兼容 ERC20Metadata
        // returnDataSize() >= 32：decimals() 对方返回的字节长度够不够 32 字节？
        // uint256(returnedDecimals) <= type(uint8).max：decimals 不可能超过 255
        return
            (success && LowLevelCall.returnDataSize() >= 32 && uint256(returnedDecimals) <= type(uint8).max)
                ? (true, uint8(uint256(returnedDecimals)))
                : (false, 0);
    }

    /**
     * @dev Decimals are computed by adding the decimal offset on top of the underlying asset's decimals. This
     * "original" value is cached during construction of the vault contract. If this read operation fails (e.g., the
     * asset has not been created yet), a default of 18 is used to represent the underlying asset's decimals.
     *
     * See {IERC20Metadata-decimals}.
     */
    function decimals() public view virtual override(IERC20Metadata, ERC20) returns (uint8) {
        return _underlyingDecimals + _decimalsOffset();
    }

    /// @inheritdoc IERC4626
    // 返回底层资产地址
    function asset() public view virtual returns (address) {
        return address(_asset);
    }

    /// @inheritdoc IERC4626
    // 读取当前合约（vault）资产余额
    // IERC20(asset()) 的意思是：“把某个地址当作一个 IERC20 合约来看，并调用它的函数。” InterfaceName(contractAddress)
    // IERC20(_asset).balanceOf() = _asset.balanceOf()，没有直接用 _asset.balanceOf,而是：IERC20(_asset), 统一通过公共函数 asset() 访问底层资产
    function totalAssets() public view virtual returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    /// @inheritdoc IERC4626
    // 资产转份额
    function convertToShares(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC4626
    // 份额转资产
    function convertToAssets(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC4626
    // 告诉用户 / 前端 / Dapp，最大可存入 assets 数量
    // 参数 address 目前没用，标准规定必须带这个参数，留给子类override使用
    function maxDeposit(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /// @inheritdoc IERC4626
    // 告诉用户 / 前端 / Dapp，最大可 mint 的 shares 数量
    function maxMint(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /// @inheritdoc IERC4626
    // 查询预览 用户owner当前拥有多少个assets
    function maxWithdraw(address owner) public view virtual returns (uint256) {
        return previewRedeem(maxRedeem(owner));
    }

    /// @inheritdoc IERC4626
    // owner 有多少 shares。
    function maxRedeem(address owner) public view virtual returns (uint256) {
        return balanceOf(owner);
    }

    /// @inheritdoc IERC4626
    // 预览 assets 当前可以兑换多少 shares
    function previewDeposit(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC4626
    // 预览 mint 这么多shares，我需要支付多少 asserts
    function previewMint(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Ceil);
    }

    /// @inheritdoc IERC4626
    // 预览 要提取 这么多 assets，需要多少shares
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }

    /// @inheritdoc IERC4626
    // 查询预览 参数shares可以兑换多少assets
    function previewRedeem(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC4626
    // 作用：用户把 X 个底层资产（USDT/WETH/USDC）存进 Vault，Vault 给 receiver 铸造 shares 作为存款凭证。
    function deposit(uint256 assets, address receiver) public virtual returns (uint256) {
        // 检查最大可存入限制
        uint256 maxAssets = maxDeposit(receiver);
        if (assets > maxAssets) {
            revert ERC4626ExceededMaxDeposit(receiver, assets, maxAssets);
        }

        // 计算当前资产可以值多少shares
        uint256 shares = previewDeposit(assets);

        // 执行deposit
        _deposit(_msgSender(), receiver, assets, shares);

        return shares;
    }

    /// @inheritdoc IERC4626
    function mint(uint256 shares, address receiver) public virtual returns (uint256) {
        uint256 maxShares = maxMint(receiver);
        if (shares > maxShares) {
            revert ERC4626ExceededMaxMint(receiver, shares, maxShares);
        }

        uint256 assets = previewMint(shares);
        _deposit(_msgSender(), receiver, assets, shares);

        return assets;
    }

    /// @inheritdoc IERC4626
    function withdraw(uint256 assets, address receiver, address owner) public virtual returns (uint256) {
        uint256 maxAssets = maxWithdraw(owner);
        if (assets > maxAssets) {
            revert ERC4626ExceededMaxWithdraw(owner, assets, maxAssets);
        }

        uint256 shares = previewWithdraw(assets);
        _withdraw(_msgSender(), receiver, owner, assets, shares);

        return shares;
    }

    /// @inheritdoc IERC4626
    function redeem(uint256 shares, address receiver, address owner) public virtual returns (uint256) {
        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) {
            revert ERC4626ExceededMaxRedeem(owner, shares, maxShares);
        }

        uint256 assets = previewRedeem(shares);
        _withdraw(_msgSender(), receiver, owner, assets, shares);

        return assets;
    }

    /**
     * @dev Internal conversion function (from assets to shares) with support for rounding direction.
     * 参数：assets：资产；
     *      rounding：枚举(Floor、Ceil、Trunc、Trunc)  Floor：向下取整  Ceil：向上取整
     * 作用：根据当前 vault 的“价格”，把要存入的资产换算成对应数量的 shares。
     *
     */
    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
        // 计算份额公式：shares = assets * (totalSupply + virtualShares) / (totalAssets + virtualAssets)
        // mulDiv(a, b, rounding) 相当于：(a × b) ÷ denominator
        return assets.mulDiv(totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1, rounding);
    }

    /**
     * @dev Internal conversion function (from shares to assets) with support for rounding direction.
     * 作用：根据当前 Vault 的汇率，把 shares 换算成底层资产（assets）。
     */
    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view virtual returns (uint256) {
        // 计算公式：assets = shares * (totalAssets+1) / (totalSupply+virtualShares)
        return shares.mulDiv(totalAssets() + 1, totalSupply() + 10 ** _decimalsOffset(), rounding);
    }

    /**
     * @dev Deposit/mint common workflow.
     */
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal virtual {
        // If asset() is ERC-777, `transferFrom` can trigger a reentrancy BEFORE the transfer happens through the
        // `tokensToSend` hook. On the other hand, the `tokenReceived` hook, that is triggered after the transfer,
        // calls the vault, which is assumed not malicious.
        //
        // Conclusion: we need to do the transfer before we mint so that any reentrancy would happen before the
        // assets are transferred and before the shares are minted, which is a valid state.
        // slither-disable-next-line reentrancy-no-eth

        // 把asserts(USDT、USDC等) 转到 vault
        _transferIn(caller, assets);

        // 给用户receiver 铸造相应的份额
        _mint(receiver, shares);

        emit Deposit(caller, receiver, assets, shares);
    }

    /**
     * @dev Withdraw/redeem common workflow.
     *
     * 作用：burn 掉用户的 shares，把真实资产asserts从 vault转给 用户。-> 赎回资产
     */
    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal virtual {
        // 如果 caller = owner（自己提自己的钱）➡ 不用检查授权
        if (caller != owner) {
            // 如果 caller != owner（别人替你提钱）➡ 必须检查 ERC20 allowance
            _spendAllowance(owner, caller, shares);
        }

        // If asset() is ERC-777, `transfer` can trigger a reentrancy AFTER the transfer happens through the
        // `tokensReceived` hook. On the other hand, the `tokensToSend` hook, that is triggered before the transfer,
        // calls the vault, which is assumed not malicious.
        //
        // Conclusion: we need to do the transfer after the burn so that any reentrancy would happen after the
        // shares are burned and after the assets are transferred, which is a valid state.

        // burn 掉 shares
        _burn(owner, shares);

        // 把真是资产转给用户
        _transferOut(receiver, assets);

        emit Withdraw(caller, receiver, owner, assets, shares);
    }

    /// @dev Performs a transfer in of underlying assets. The default implementation uses `SafeERC20`. Used by {_deposit}.
    // 作用：把底层资产（USDT/USDC/WETH）从用户钱包转进 Vault 合约地址
    function _transferIn(address from, uint256 assets) internal virtual {
        // 操作 底层合约_asset，执行safeTransferFrom() 转账，把用户的token转入vault
        SafeERC20.safeTransferFrom(IERC20(asset()), from, address(this), assets);
    }

    /// @dev Performs a transfer out of underlying assets. The default implementation uses `SafeERC20`. Used by {_withdraw}.
    // 把底层资产（USDT/USDC/WETH）从 Vault 合约地址转给用户
    function _transferOut(address to, uint256 assets) internal virtual {
        // 操作 底层合约_asset，执行safeTransferFrom() 转账，把token 从 vault 提取给用户
        SafeERC20.safeTransfer(IERC20(asset()), to, assets);
    }

    function _decimalsOffset() internal view virtual returns (uint8) {
        return 0;
    }
}
