// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (access/manager/AccessManager.sol)

pragma solidity ^0.8.20;

import {IAccessManager} from "./IAccessManager.sol";
import {IAccessManaged} from "./IAccessManaged.sol";
import {Address} from "../../utils/Address.sol";
import {Context} from "../../utils/Context.sol";
import {Multicall} from "../../utils/Multicall.sol";
import {Math} from "../../utils/math/Math.sol";
import {Time} from "../../utils/types/Time.sol";
import {Hashes} from "../../utils/cryptography/Hashes.sol";

/**
 * @dev AccessManager is a central contract to store the permissions of a system.
 *
 * A smart contract under the control of an AccessManager instance is known as a target, and will inherit from the
 * {AccessManaged} contract, be connected to this contract as its manager and implement the {AccessManaged-restricted}
 * modifier on a set of functions selected to be permissioned. Note that any function without this setup won't be
 * effectively restricted.
 *
 * The restriction rules for such functions are defined in terms of "roles" identified by an `uint64` and scoped
 * by target (`address`) and function selectors (`bytes4`). These roles are stored in this contract and can be
 * configured by admins (`ADMIN_ROLE` members) after a delay (see {getTargetAdminDelay}).
 *
 * For each target contract, admins can configure the following without any delay:
 *
 * * The target's {AccessManaged-authority} via {updateAuthority}.
 * * Close or open a target via {setTargetClosed} keeping the permissions intact.
 * * The roles that are allowed (or disallowed) to call a given function (identified by its selector) through {setTargetFunctionRole}.
 *
 * By default every address is member of the `PUBLIC_ROLE` and every target function is restricted to the `ADMIN_ROLE` until configured otherwise.
 * Additionally, each role has the following configuration options restricted to this manager's admins:
 *
 * * A role's admin role via {setRoleAdmin} who can grant or revoke roles.
 * * A role's guardian role via {setRoleGuardian} who's allowed to cancel operations.
 * * A delay in which a role takes effect after being granted through {setGrantDelay}.
 * * A delay of any target's admin action via {setTargetAdminDelay}.
 * * A role label for discoverability purposes with {labelRole}.
 *
 * Any account can be added and removed into any number of these roles by using the {grantRole} and {revokeRole} functions
 * restricted to each role's admin (see {getRoleAdmin}).
 *
 * Since all the permissions of the managed system can be modified by the admins of this instance, it is expected that
 * they will be highly secured (e.g., a multisig or a well-configured DAO).
 *
 * NOTE: This contract implements a form of the {IAuthority} interface, but {canCall} has additional return data so it
 * doesn't inherit `IAuthority`. It is however compatible with the `IAuthority` interface since the first 32 bytes of
 * the return data are a boolean as expected by that interface.
 *
 * NOTE: Systems that implement other access control mechanisms (for example using {Ownable}) can be paired with an
 * {AccessManager} by transferring permissions (ownership in the case of {Ownable}) directly to the {AccessManager}.
 * Users will be able to interact with these contracts through the {execute} function, following the access rules
 * registered in the {AccessManager}. Keep in mind that in that context, the msg.sender seen by restricted functions
 * will be {AccessManager} itself.
 *
 * WARNING: When granting permissions over an {Ownable} or {AccessControl} contract to an {AccessManager}, be very
 * mindful of the danger associated with functions such as {Ownable-renounceOwnership} or
 * {AccessControl-renounceRole}.
 */

/**
 * 继承了：
 *  - Context：提供 _msgSender()、_msgData() 等上下文工具。
 *  - Multicall：支持批量调用（一次执行多个函数）。
 *  - IAccessManager：接口定义。
 * 
 * 使用了多个工具库：时间延迟、哈希计算、数学运算等。
 */
contract AccessManager is Context, Multicall, IAccessManager {
    using Time for *;

    // Structure that stores the details for a target contract.
    // 每个被管理的“目标合约”的配置
    struct TargetConfig {
        // 记录某个函数选择器（bytes4）允许哪个角色调用。
        // ⚠️ 注意：并不是所有函数选择器都有记录，未记录的函数选择器默认只能被 ADMIN_ROLE 调用。因为未被记录的函数选择器在 canCall 中会返回 0 角色 ID。
        //         一个函数只能对应一个角色
        mapping(bytes4 selector => uint64 roleId) allowedRoles;
        // 设置对该 target 管理操作的延迟时间
        Time.Delay adminDelay;
        // 是否关闭对该 target 的访问
        bool closed;
    }

    // Structure that stores the details for a role/account pair. This structure fits into a single slot.
    // 某个角色对某个账户的访问权限配置
    struct Access {
        // Timepoint at which the user gets the permission.
        // If this is either 0 or in the future, then the role permission is not available.
        // 授权生效时间点
        uint48 since;
        // Delay for execution. Only applies to restricted() / execute() calls.
        // 最小强制等待时间，schedule函数执行时可以传when，但是必须大于 now + delay
        // 如果delay = 0，表示不允许排队调用（只能立即调用或者拒绝调用）
        Time.Delay delay;
    }

    // Structure that stores the details of a role.
    // 角色配置
    struct Role {
        // Members of the role.
        // 该角色下所有成员及其Access配置
        mapping(address user => Access access) members;
        // Admin who can grant or revoke permissions.
        // 该角色的管理员角色（能授予/撤销此角色）。
        uint64 admin;
        // Guardian who can cancel operations targeting functions that need this role.
        // 守护者角色（可取消操作）。
        uint64 guardian;
        // Delay in which the role takes effect after being granted.
        // 授予该角色后的生效延迟。
        Time.Delay grantDelay;
    }

    // Structure that stores the details for a scheduled operation. This structure fits into a single slot.
    // 延迟操作的调度信息
    struct Schedule {
        // Moment at which the operation can be executed.
        uint48 timepoint;
        // Operation nonce to allow third-party contracts to identify the operation.
        // nonce 不是用来防止重复排期的, 它的作用是：🔹 区分同一个操作（operationId）被多次排期、执行或取消的不同版本，或者说执行序号，区分第几次排期
        // 操作的 nonce，用来让其他（第三方）合约能够识别具体是哪一次操作。 比如：发起了个schedule，返回nonce，下次去查这个操作的状态时，就能知道是哪个版本的操作了。
        uint32 nonce;
    }

    /**
     * @dev The identifier of the admin role. Required to perform most configuration operations including
     * other roles' management and target restrictions.
     * ADMIN_ROLE 拥有系统最高权限，能修改角色、延迟、target 配置
     */
    uint64 public constant ADMIN_ROLE = type(uint64).min; // 0

    /**
     * @dev The identifier of the public role. Automatically granted to all addresses with no delay.
     * 默认所有地址拥有的公共角色
     */
    uint64 public constant PUBLIC_ROLE = type(uint64).max; // 2**64-1

    // 目标合约地址 到 目标配置 的映射
    mapping(address target => TargetConfig mode) private _targets;
    // 角色ID 到 角色配置 的映射
    mapping(uint64 roleId => Role) private _roles;
    // 延迟操作ID 到 调度信息 的映射
    mapping(bytes32 operationId => Schedule) private _schedules;

    // Used to identify operations that are currently being executed via {execute}.
    // This should be transient storage when supported by the EVM.
    // _executionId 代表正在执行哪一个函数（target， selector）
    bytes32 private _executionId;

    /**
     * @dev Check that the caller is authorized to perform the operation.
     * See {AccessManager} description for a detailed breakdown of the authorization logic.
     */
    modifier onlyAuthorized() {
        _checkAuthorized();
        _;
    }

    constructor(address initialAdmin) {
        if (initialAdmin == address(0)) {
            revert AccessManagerInvalidInitialAdmin(address(0));
        }

        // admin is active immediately and without any execution delay.
        _grantRole(ADMIN_ROLE, initialAdmin, 0, 0);
    }

    // =================================================== GETTERS ====================================================

    /**
     *  判断一个调用者（caller）能不能调用目标合约（target）的某个函数（selector）
     *  returns:
     *    immediate: 是否可以立即调用（无延迟）
     *    delay: 调用延迟时间
     */
    /// @inheritdoc IAccessManager
    function canCall(
        address caller,
        address target,
        bytes4 selector
    ) public view virtual returns (bool immediate, uint32 delay) {
        // 如果目标合约被关闭，任何人都不能调用
        if (isTargetClosed(target)) {
            return (false, 0);
        } else if (caller == address(this)) {
            // Caller is AccessManager, this means the call was sent through {execute} and it already checked
            // permissions. We verify that the call "identifier", which is set during {execute}, is correct.

            // 如果调用者是 AccessManager 自己
            return (_isExecuting(target, selector), 0);
        } else {
            // 普通用户通过受控合约调用时
            // 获取当前合约，当前函数的 roleId
            uint64 roleId = getTargetFunctionRole(target, selector);
            // 检查调用者是否拥有该角色
            (bool isMember, uint32 currentDelay) = hasRole(roleId, caller);
            // - 如果调用者拥有该角色 -〉
            //      - 如果延迟是0 -> 允许立即调用
            //      - 否则必须延迟执行（schedule → execute）
            // - 如果没有该角色 -〉拒绝执行 
            return isMember ? (currentDelay == 0, currentDelay) : (false, 0);
        }
    }

    /// @inheritdoc IAccessManager
    // 当一个操作到达**可执行时间点（timepoint）**之后，你有 1 周的时间窗口 去调用 execute()。
    // 如果超出这 1 周还没执行，这个操作就会被视为“过期”，不能再执行，也不能再取消，只能重新安排（重新 schedule）
    function expiration() public view virtual returns (uint32) {
        return 1 weeks;
    }

    /// @inheritdoc IAccessManager
    function minSetback() public view virtual returns (uint32) {
        return 5 days;
    }

    /// @inheritdoc IAccessManager
    function isTargetClosed(address target) public view virtual returns (bool) {
        return _targets[target].closed;
    }

    /// @inheritdoc IAccessManager
    function getTargetFunctionRole(address target, bytes4 selector) public view virtual returns (uint64) {
        return _targets[target].allowedRoles[selector];
    }

    /// @inheritdoc IAccessManager
    function getTargetAdminDelay(address target) public view virtual returns (uint32) {
        return _targets[target].adminDelay.get();
    }

    /// @inheritdoc IAccessManager
    function getRoleAdmin(uint64 roleId) public view virtual returns (uint64) {
        return _roles[roleId].admin;
    }

    /// @inheritdoc IAccessManager
    function getRoleGuardian(uint64 roleId) public view virtual returns (uint64) {
        return _roles[roleId].guardian;
    }

    /// @inheritdoc IAccessManager
    function getRoleGrantDelay(uint64 roleId) public view virtual returns (uint32) {
        return _roles[roleId].grantDelay.get();
    }

    /// @inheritdoc IAccessManager
    // 获取某个用户在某个角色下的访问权限信息
    // 返回值：since（授权生效时间点）、currentDelay（当前执行延迟）、pendingDelay（待生效的执行延迟）、effect（待生效时间点）
    function getAccess(
        uint64 roleId,
        address account
    ) public view virtual returns (uint48 since, uint32 currentDelay, uint32 pendingDelay, uint48 effect) {
        Access storage access = _roles[roleId].members[account];

        since = access.since;
        (currentDelay, pendingDelay, effect) = access.delay.getFull();

        return (since, currentDelay, pendingDelay, effect);
    }

    /// @inheritdoc IAccessManager
    // check whether the second parameter 'account' has the role 'roleId', which is the first parameter
    // returns：isMember：是否拥有该角色；executionDelay：执行该角色权限所需的延迟时间
    function hasRole(
        uint64 roleId,
        address account
    ) public view virtual returns (bool isMember, uint32 executionDelay) {
        if (roleId == PUBLIC_ROLE) {
            return (true, 0);
        } else {
            // hasRoleSince:从哪个时间点开始拥有该角色; currentDelay:执行该角色权限所需的延迟时间
            (uint48 hasRoleSince, uint32 currentDelay, , ) = getAccess(roleId, account);
            // hasRoleSince != 0：是否曾被授予该角色（0 表示从未授予）。
            // 是否已到生效时间（因为授予角色时可以设置“延迟生效”）。
            return (hasRoleSince != 0 && hasRoleSince <= Time.timestamp(), currentDelay);
        }
    }

    // =============================================== ROLE MANAGEMENT ===============================================
    /// @inheritdoc IAccessManager
    function labelRole(uint64 roleId, string calldata label) public virtual onlyAuthorized {
        if (roleId == ADMIN_ROLE || roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }
        emit RoleLabel(roleId, label);
    }

    /// @inheritdoc IAccessManager
    function grantRole(uint64 roleId, address account, uint32 executionDelay) public virtual onlyAuthorized {
        _grantRole(roleId, account, getRoleGrantDelay(roleId), executionDelay);
    }

    /// @inheritdoc IAccessManager
    function revokeRole(uint64 roleId, address account) public virtual onlyAuthorized {
        _revokeRole(roleId, account);
    }

    /// @inheritdoc IAccessManager
    function renounceRole(uint64 roleId, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessManagerBadConfirmation();
        }
        _revokeRole(roleId, callerConfirmation);
    }

    /// @inheritdoc IAccessManager
    function setRoleAdmin(uint64 roleId, uint64 admin) public virtual onlyAuthorized {
        _setRoleAdmin(roleId, admin);
    }

    /// @inheritdoc IAccessManager
    function setRoleGuardian(uint64 roleId, uint64 guardian) public virtual onlyAuthorized {
        _setRoleGuardian(roleId, guardian);
    }

    /// @inheritdoc IAccessManager
    function setGrantDelay(uint64 roleId, uint32 newDelay) public virtual onlyAuthorized {
        _setGrantDelay(roleId, newDelay);
    }

    /**
     * @dev Internal version of {grantRole} without access control. Returns true if the role was newly granted.
     *
     * Emits a {RoleGranted} event.
     */
    function _grantRole(
        uint64 roleId,
        address account,
        uint32 grantDelay,
        uint32 executionDelay
    ) internal virtual returns (bool) {
        if (roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }

        bool newMember = _roles[roleId].members[account].since == 0;
        uint48 since;

        if (newMember) {
            since = Time.timestamp() + grantDelay;
            _roles[roleId].members[account] = Access({since: since, delay: executionDelay.toDelay()});
        } else {
            // No setback here. Value can be reset by doing revoke + grant, effectively allowing the admin to perform
            // any change to the execution delay within the duration of the role admin delay.
            (_roles[roleId].members[account].delay, since) = _roles[roleId].members[account].delay.withUpdate(
                executionDelay,
                0
            );
        }

        emit RoleGranted(roleId, account, executionDelay, since, newMember);
        return newMember;
    }

    /**
     * @dev Internal version of {revokeRole} without access control. This logic is also used by {renounceRole}.
     * Returns true if the role was previously granted.
     *
     * Emits a {RoleRevoked} event if the account had the role.
     */
    function _revokeRole(uint64 roleId, address account) internal virtual returns (bool) {
        if (roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }

        if (_roles[roleId].members[account].since == 0) {
            return false;
        }

        // 恢复默认值 0
        delete _roles[roleId].members[account];

        emit RoleRevoked(roleId, account);
        return true;
    }

    /**
     * @dev Internal version of {setRoleAdmin} without access control.
     *
     * Emits a {RoleAdminChanged} event.
     *
     * NOTE: Setting the admin role as the `PUBLIC_ROLE` is allowed, but it will effectively allow
     * anyone to set grant or revoke such role.
     */
    function _setRoleAdmin(uint64 roleId, uint64 admin) internal virtual {
        if (roleId == ADMIN_ROLE || roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }

        _roles[roleId].admin = admin;

        emit RoleAdminChanged(roleId, admin);
    }

    /**
     * @dev Internal version of {setRoleGuardian} without access control.
     *
     * Emits a {RoleGuardianChanged} event.
     *
     * NOTE: Setting the guardian role as the `PUBLIC_ROLE` is allowed, but it will effectively allow
     * anyone to cancel any scheduled operation for such role.
     */
    function _setRoleGuardian(uint64 roleId, uint64 guardian) internal virtual {
        if (roleId == ADMIN_ROLE || roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }

        _roles[roleId].guardian = guardian;

        emit RoleGuardianChanged(roleId, guardian);
    }

    /**
     * @dev Internal version of {setGrantDelay} without access control.
     *
     * Emits a {RoleGrantDelayChanged} event.
     */
    function _setGrantDelay(uint64 roleId, uint32 newDelay) internal virtual {
        if (roleId == PUBLIC_ROLE) {
            revert AccessManagerLockedRole(roleId);
        }

        uint48 effect;
        (_roles[roleId].grantDelay, effect) = _roles[roleId].grantDelay.withUpdate(newDelay, minSetback());

        emit RoleGrantDelayChanged(roleId, newDelay, effect);
    }

    // ============================================= FUNCTION MANAGEMENT ==============================================
    /// @inheritdoc IAccessManager
    function setTargetFunctionRole(
        address target,
        bytes4[] calldata selectors,
        uint64 roleId
    ) public virtual onlyAuthorized {
        for (uint256 i = 0; i < selectors.length; ++i) {
            _setTargetFunctionRole(target, selectors[i], roleId);
        }
    }

    /**
     * @dev Internal version of {setTargetFunctionRole} without access control.
     *
     * Emits a {TargetFunctionRoleUpdated} event.
     */
    function _setTargetFunctionRole(address target, bytes4 selector, uint64 roleId) internal virtual {
        _targets[target].allowedRoles[selector] = roleId;
        emit TargetFunctionRoleUpdated(target, selector, roleId);
    }

    /// @inheritdoc IAccessManager
    function setTargetAdminDelay(address target, uint32 newDelay) public virtual onlyAuthorized {
        _setTargetAdminDelay(target, newDelay);
    }

    /**
     * @dev Internal version of {setTargetAdminDelay} without access control.
     *
     * Emits a {TargetAdminDelayUpdated} event.
     */
    function _setTargetAdminDelay(address target, uint32 newDelay) internal virtual {
        uint48 effect;
        // 多个返回值同时赋值（tuple assignment）
        (_targets[target].adminDelay, effect) = _targets[target].adminDelay.withUpdate(newDelay, minSetback());

        emit TargetAdminDelayUpdated(target, newDelay, effect);
    }

    // =============================================== MODE MANAGEMENT ================================================
    /// @inheritdoc IAccessManager
    function setTargetClosed(address target, bool closed) public virtual onlyAuthorized {
        _setTargetClosed(target, closed);
    }

    /**
     * @dev Set the closed flag for a contract. This is an internal setter with no access restrictions.
     *
     * Emits a {TargetClosed} event.
     */
    function _setTargetClosed(address target, bool closed) internal virtual {
        _targets[target].closed = closed;
        emit TargetClosed(target, closed);
    }

    // ============================================== DELAYED OPERATIONS ==============================================
    /// @inheritdoc IAccessManager
    function getSchedule(bytes32 id) public view virtual returns (uint48) {
        uint48 timepoint = _schedules[id].timepoint;
        return _isExpired(timepoint) ? 0 : timepoint;
    }

    /// @inheritdoc IAccessManager
    function getNonce(bytes32 id) public view virtual returns (uint32) {
        return _schedules[id].nonce;
    }

    /// @inheritdoc IAccessManager
    // para:
    //   1.target: 要调用的合约地址
    //   2.data: 调用数据，（包含 4 字节 selector + 编码参数）
    //   3.when：请求的执行时间（UNIX 秒）。允许传 0（表示“未指定具体时间”，用系统算的最早时间: now + delay）
    function schedule(
        address target,
        bytes calldata data,
        uint48 when
    ) public virtual returns (bytes32 operationId, uint32 nonce) {
        address caller = _msgSender();

        // Fetch restrictions that apply to the caller on the targeted function
        // setback 来源于结构体Access中的delay字段
        (, uint32 setback) = _canCallExtended(caller, target, data);

        // 计算最早允许的执行时间：当前时间 + 延迟
        uint48 minWhen = Time.timestamp() + setback;

        // If call with delay is not authorized, or if requested timing is too soon, revert
        // 情况1: setback == 0，说明该调用者不需要延迟就能直接调用（或不被允许排队），此处不允许 schedule
        // 情况2: 你传了 when > 0，但比系统要求的 minWhen 还早 → 你想“偷跑时间”，拒绝。
        if (setback == 0 || (when > 0 && when < minWhen)) {
            revert AccessManagerUnauthorizedCall(caller, target, _checkSelector(data));
        }

        // Reuse variable due to stack too deep
        // 若你没指定时间（传 0），就用 minWhen；若你给了更晚的时间，也尊重你（取两者较大值）。
        when = uint48(Math.max(when, minWhen)); // cast is safe: both inputs are uint48

        // If caller is authorised, schedule operation
        // 生成本次计划的唯一 ID，确保绑定到谁排的、要调谁、调什么。
        operationId = hashOperation(caller, target, data);

        // 确保该操作当前未处于已登记状态（即之前没排过队，或之前排的队已过期）
        _checkNotScheduled(operationId);

        // unchecked: Solidity 新版本（^0.8.x）新增功能，禁用溢出检查
        // 因为：在 1000 年内要让 nonce 溢出几乎不可能。所以，不用溢出检查
        unchecked {
            // It's not feasible to overflow the nonce in less than 1000 years
            nonce = _schedules[operationId].nonce + 1;
        }
        _schedules[operationId].timepoint = when;
        _schedules[operationId].nonce = nonce;
        emit OperationScheduled(operationId, nonce, when, caller, target, data);

        // Using named return values because otherwise we get stack too deep
    }

    /**
     * @dev Reverts if the operation is currently scheduled and has not expired.
     *
     * NOTE: This function was introduced due to stack too deep errors in schedule.
     * background: 在 AccessManager 里，同一个操作（相同 caller + target + data） 只能同时存在一个有效的计划。 
     *             只有当该计划到期或过期后，才能再次调用 schedule() 重新安排。
     */
    function _checkNotScheduled(bytes32 operationId) private view {
        uint48 prevTimepoint = _schedules[operationId].timepoint;

        // 存在有效的调度计划，且未过期，拒绝再次调度
        if (prevTimepoint != 0 && !_isExpired(prevTimepoint)) {
            revert AccessManagerAlreadyScheduled(operationId);
        }
    }

    /// @inheritdoc IAccessManager
    // Reentrancy is not an issue because permissions are checked on msg.sender. Additionally,
    // _consumeScheduledOp guarantees a scheduled operation is only executed once.
    // slither-disable-next-line reentrancy-no-eth
    // target: 要调用功能的目标合约地址 
    // data: 调用数据（包含 4 字节 selector + 编码参数）
    function execute(address target, bytes calldata data) public payable virtual returns (uint32) {
        address caller = _msgSender();

        // Fetch restrictions that apply to the caller on the targeted function
        (bool immediate, uint32 setback) = _canCallExtended(caller, target, data);

        // If call is not authorized, revert
        // immediate = false && setback = 0，说明调用者既不能立即调用，也不能排队调用
        if (!immediate && setback == 0) {
            revert AccessManagerUnauthorizedCall(caller, target, _checkSelector(data));
        }
        bytes32 operationId = hashOperation(caller, target, data);
        uint32 nonce;

        // If caller is authorised, check operation was scheduled early enough
        // Consume an available schedule even if there is no currently enforced delay
        // 如果这笔调用有延迟（setback ≠ 0），或者它之前确实被 schedule() 登记过，那么就必须消费掉那次排期。
        if (setback != 0 || getSchedule(operationId) != 0) {
            // 会检查时间是否已到、计划是否未取消、计划是否未过期等, 并标记已消费（delete timepoint）， 并返回该操作的 nonce
            nonce = _consumeScheduledOp(operationId);
        }

        // Mark the target and selector as authorised
        // 先临时记录一下_executionId，等到Address.functionCallWithValue执行之后，再拿过来
        bytes32 executionIdBefore = _executionId;
        // 标记当前正在执行的目标函数
        _executionId = _hashExecutionId(target, _checkSelector(data));

        // Perform call
        // 用户execute发起调用 -> AccessManager -> 目标合约.call
        // 比如：我要调用erc20合约的一个sign函数，实际上是先调用AccessManager的execute函数，
        //      然后AccessManager再去调用erc20合约的sign函数。
        Address.functionCallWithValue(target, data, msg.value);

        // Reset execute identifier
        _executionId = executionIdBefore;

        return nonce;
    }

    /// @inheritdoc IAccessManager
    function cancel(address caller, address target, bytes calldata data) public virtual returns (uint32) {
        address msgsender = _msgSender();
        bytes4 selector = _checkSelector(data);

        bytes32 operationId = hashOperation(caller, target, data);
        if (_schedules[operationId].timepoint == 0) {
            revert AccessManagerNotScheduled(operationId);
        } else if (caller != msgsender) {
            // calls can only be canceled by the account that scheduled them, a global admin, or by a guardian of the required role.
            (bool isAdmin, ) = hasRole(ADMIN_ROLE, msgsender);
            (bool isGuardian, ) = hasRole(getRoleGuardian(getTargetFunctionRole(target, selector)), msgsender);
            if (!isAdmin && !isGuardian) {
                revert AccessManagerUnauthorizedCancel(msgsender, caller, target, selector);
            }
        }

        delete _schedules[operationId].timepoint; // reset the timepoint, keep the nonce
        uint32 nonce = _schedules[operationId].nonce;
        emit OperationCanceled(operationId, nonce);

        return nonce;
    }

    /// @inheritdoc IAccessManager
    function consumeScheduledOp(address caller, bytes calldata data) public virtual {
        address target = _msgSender();
        if (IAccessManaged(target).isConsumingScheduledOp() != IAccessManaged.isConsumingScheduledOp.selector) {
            revert AccessManagerUnauthorizedConsume(target);
        }
        _consumeScheduledOp(hashOperation(caller, target, data));
    }

    /**
     * @dev Internal variant of {consumeScheduledOp} that operates on bytes32 operationId.
     *
     * Returns the nonce of the scheduled operation that is consumed.
     * 作用：✅ 在执行（execute）操作时，验证该操作是否已排期、到期、未过期，并将其标记为“已消耗（已执行）”。
     */
    function _consumeScheduledOp(bytes32 operationId) internal virtual returns (uint32) {
        uint48 timepoint = _schedules[operationId].timepoint;
        uint32 nonce = _schedules[operationId].nonce;

        if (timepoint == 0) {
            // timepoint 是 0，表示这个操作根本没排过期
            revert AccessManagerNotScheduled(operationId);
        } else if (timepoint > Time.timestamp()) {
            // 说明执行太早，还没到可以执行的时间点
            revert AccessManagerNotReady(operationId);
        } else if (_isExpired(timepoint)) {
            // 说明执行太晚，已经过了允许的执行时间窗口(超过了可以执行的一周)
            revert AccessManagerExpired(operationId);
        }

        // 重置为0，相当于标记为未排期状态
        delete _schedules[operationId].timepoint; // reset the timepoint, keep the nonce
        emit OperationExecuted(operationId, nonce);

        return nonce;
    }

    /// @inheritdoc IAccessManager
    function hashOperation(address caller, address target, bytes calldata data) public view virtual returns (bytes32) {
        return keccak256(abi.encode(caller, target, data));
    }

    // ==================================================== OTHERS ====================================================
    /// @inheritdoc IAccessManager
    function updateAuthority(address target, address newAuthority) public virtual onlyAuthorized {
        IAccessManaged(target).setAuthority(newAuthority);
    }

    // ================================================= ADMIN LOGIC ==================================================
    /**
     * @dev Check if the current call is authorized according to admin and roles logic.
     *
     * WARNING: Carefully review the considerations of {AccessManaged-restricted} since they apply to this modifier.
     */
    function _checkAuthorized() private {
        address caller = _msgSender();
        (bool immediate, uint32 delay) = _canCallSelf(caller, _msgData());
        if (!immediate) {
            if (delay == 0) {
                (, uint64 requiredRole, ) = _getAdminRestrictions(_msgData());
                revert AccessManagerUnauthorizedAccount(caller, requiredRole);
            } else {
                _consumeScheduledOp(hashOperation(caller, address(this), _msgData()));
            }
        }
    }

    /**
     * @dev Get the admin restrictions of a given function call based on the function and arguments involved.
     *
     * Returns:
     * - bool restricted: does this data match a restricted operation
     * - uint64: which role is this operation restricted to
     * - uint32: minimum delay to enforce for that operation (max between operation's delay and admin's execution delay)
     */
    function _getAdminRestrictions(
        bytes calldata data
    ) private view returns (bool adminRestricted, uint64 roleAdminId, uint32 executionDelay) {
        if (data.length < 4) {
            return (false, 0, 0);
        }

        bytes4 selector = _checkSelector(data);

        // Restricted to ADMIN with no delay beside any execution delay the caller may have
        if (
            selector == this.labelRole.selector ||
            selector == this.setRoleAdmin.selector ||
            selector == this.setRoleGuardian.selector ||
            selector == this.setGrantDelay.selector ||
            selector == this.setTargetAdminDelay.selector
        ) {
            return (true, ADMIN_ROLE, 0);
        }

        // Restricted to ADMIN with the admin delay corresponding to the target
        if (
            selector == this.updateAuthority.selector ||
            selector == this.setTargetClosed.selector ||
            selector == this.setTargetFunctionRole.selector
        ) {
            // First argument is a target.
            address target = abi.decode(data[0x04:0x24], (address));
            uint32 delay = getTargetAdminDelay(target);
            return (true, ADMIN_ROLE, delay);
        }

        // Restricted to that role's admin with no delay beside any execution delay the caller may have.
        if (selector == this.grantRole.selector || selector == this.revokeRole.selector) {
            // First argument is a roleId.
            uint64 roleId = abi.decode(data[0x04:0x24], (uint64));
            return (true, getRoleAdmin(roleId), 0);
        }

        return (false, getTargetFunctionRole(address(this), selector), 0);
    }

    // =================================================== HELPERS ====================================================
    /**
     * @dev An extended version of {canCall} for internal usage that checks {_canCallSelf}
     * when the target is this contract.
     *
     * Returns:
     * - bool immediate: whether the operation can be executed immediately (with no delay)
     * - uint32 delay: the execution delay
     */
    function _canCallExtended(
        address caller,  // 调用者地址
        address target,  // 目标合约地址
        bytes calldata data  // 调用数据
    ) private view returns (bool immediate, uint32 delay) {
        if (target == address(this)) {
            // 如果调用的目标就是 AccessManager 自己
            // 因为 AccessManager 也有自己的管理函数（如 grantRole, setDelay, schedule, execute 等），
            // 它们不能和普通受控合约一样判断，否则可能引起递归调用或逻辑混乱。
            // 所以自调用（self-call）走单独逻辑 _canCallSelf()，
            // 那里面有额外规则，比如管理员才能调用、部分函数允许内部操作等。
            return _canCallSelf(caller, data);
        } else {
            // data.length < 4: 不是一个合法的函数调用 → 拒绝。
            // 否则调用普通的 canCall() 来判断权限。
            return data.length < 4 ? (false, 0) : canCall(caller, target, _checkSelector(data));
        }
    }

    /**
     * @dev A version of {canCall} that checks for restrictions in this contract.
     */
    function _canCallSelf(address caller, bytes calldata data) private view returns (bool immediate, uint32 delay) {
        if (data.length < 4) {
            return (false, 0);
        }

        if (caller == address(this)) {
            // Caller is AccessManager, this means the call was sent through {execute} and it already checked
            // permissions. We verify that the call "identifier", which is set during {execute}, is correct.
            return (_isExecuting(address(this), _checkSelector(data)), 0);
        }

        (bool adminRestricted, uint64 roleId, uint32 operationDelay) = _getAdminRestrictions(data);

        // isTargetClosed apply to non-admin-restricted function
        if (!adminRestricted && isTargetClosed(address(this))) {
            return (false, 0);
        }

        (bool inRole, uint32 executionDelay) = hasRole(roleId, caller);
        if (!inRole) {
            return (false, 0);
        }

        // downcast is safe because both options are uint32
        delay = uint32(Math.max(operationDelay, executionDelay));
        return (delay == 0, delay);
    }

    /**
     * @dev Returns true if a call with `target` and `selector` is being executed via {executed}.
     */
    function _isExecuting(address target, bytes4 selector) private view returns (bool) {
        return _executionId == _hashExecutionId(target, selector);
    }

    /**
     * @dev Returns true if a schedule timepoint is past its expiration deadline.
     */
    function _isExpired(uint48 timepoint) private view returns (bool) {
        // 如果这个操作已经安排过，且当前时间还没超过（计划时间 + 1 周）, 就认为这个操作仍然有效，不允许重新安排。
        return timepoint + expiration() <= Time.timestamp();
    }

    /**
     * @dev Extracts the selector from calldata. Panics if data is not at least 4 bytes
     *  获取函数的选择器
     *  每次调用函数时，调用数据的前4个字节是函数选择器（function selector），用于标识要调用的具体函数。
     */
    function _checkSelector(bytes calldata data) private pure returns (bytes4) {
        return bytes4(data[0:4]);
    }

    /**
     * @dev Hashing function for execute protection
     * target: 要调用的合约地址
     * selector: 要调用的函数选择器
     */
    function _hashExecutionId(address target, bytes4 selector) private pure returns (bytes32) {
        // address 类型是 20 字节（160 位），地址类型
        // address 地址类型 无法直接转成 uint256，必须先到转换为一个等宽整数类型 uint160，再转为 uint256
        return Hashes.efficientKeccak256(bytes32(uint256(uint160(target))), selector);
    }
}
