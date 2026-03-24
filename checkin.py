#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
    """加载余额hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:  # nosec B110
        pass
    return None


def save_balance_hash(balance_hash):
    """保存余额hash"""
    try:
        with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
            f.write(balance_hash)
    except Exception as e:
        print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
    """生成余额数据的hash"""
    # 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
    simple_balances = {
        k: v['quota']
        for k, v in balances.items()
    } if balances else {}
    balance_json = json.dumps(simple_balances,
                              sort_keys=True,
                              separators=(',', ':'))
    return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
    """解析 cookies 数据"""
    if isinstance(cookies_data, dict):
        return cookies_data

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


def normalize_access_token(token: str) -> str:
    """规范化访问令牌，去掉 Bearer 前缀。"""
    cleaned = token.strip()
    if cleaned.lower().startswith('bearer '):
        return cleaned[7:].strip()
    return cleaned


def apply_access_token_auth(client: httpx.Client, headers: dict,
                            raw_token: str):
    """将访问令牌应用到 cookie 与请求头，提升兼容性。"""
    token = normalize_access_token(raw_token)
    if not token:
        return

    # 某些 NewAPI 站点要求 session cookie
    client.cookies.set('session', token)

    # 另一些站点可能接受 Authorization / token / x-api-key
    headers['Authorization'] = f'Bearer {token}'
    headers['token'] = token
    headers['x-api-key'] = token


def _extract_session_token(payload: dict) -> str:
    """从登录响应中提取 session token。"""
    data = payload.get('data')

    if isinstance(data, str) and data.strip():
        return data.strip()

    if isinstance(data, dict):
        for key in ('token', 'access_token', 'session', 'jwt_token'):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    for key in ('token', 'access_token', 'session', 'jwt_token'):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return ''


async def get_waf_cookies_with_playwright(account_name: str, login_url: str,
                                          required_cookies: list[str]):
    """使用 Playwright 获取 WAF cookies（隐私模式）"""
    print(
        f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

    async with async_playwright() as p:
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=temp_dir,
                headless=False,
                user_agent=
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                viewport={
                    'width': 1920,
                    'height': 1080
                },
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--no-sandbox',
                ],
            )

            page = await context.new_page()

            try:
                print(
                    f'[PROCESSING] {account_name}: Access login page to get initial cookies...'
                )

                await page.goto(login_url, wait_until='networkidle')

                try:
                    await page.wait_for_function(
                        'document.readyState === "complete"', timeout=5000)
                except Exception:
                    await page.wait_for_timeout(3000)

                cookies = await page.context.cookies()

                waf_cookies = {}
                for cookie in cookies:
                    cookie_name = cookie.get('name')
                    cookie_value = cookie.get('value')
                    if cookie_name in required_cookies and cookie_value is not None:
                        waf_cookies[cookie_name] = cookie_value

                print(
                    f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies'
                )

                missing_cookies = [
                    c for c in required_cookies if c not in waf_cookies
                ]

                if missing_cookies:
                    print(
                        f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}'
                    )
                    await context.close()
                    return None

                print(
                    f'[SUCCESS] {account_name}: Successfully got all WAF cookies'
                )

                await context.close()

                return waf_cookies

            except Exception as e:
                print(
                    f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}'
                )
                await context.close()
                return None


def login_with_credentials(client, account_name: str, provider_config,
                           username: str, password: str) -> tuple[bool, str]:
    """使用用户名和密码登录，将会话写入 client.cookies。

	返回: (是否成功, 失败原因)
	"""
    print(f'[AUTH] {account_name}: Logging in with credentials...')

    user_agent = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
    )

    login_paths = ['/api/user/login', '/api/login', '/api/auth/login']
    payload_candidates = [
        {
            'username': username,
            'password': password
        },
        {
            'email': username,
            'password': password
        },
        {
            'account': username,
            'password': password
        },
        {
            'username': username,
            'passwd': password
        },
    ]

    last_error = 'Unknown login error'

    for path in login_paths:
        login_url = f'{provider_config.domain}{path}'
        for payload in payload_candidates:
            for request_mode in ('json', 'form'):
                try:
                    headers = {'User-Agent': user_agent}
                    if request_mode == 'json':
                        headers['Content-Type'] = 'application/json'
                        response = client.post(login_url,
                                               json=payload,
                                               headers=headers,
                                               timeout=30)
                    else:
                        headers[
                            'Content-Type'] = 'application/x-www-form-urlencoded'
                        response = client.post(login_url,
                                               data=payload,
                                               headers=headers,
                                               timeout=30)

                    # 优先判断 Set-Cookie 场景
                    if client.cookies.get('session'):
                        print(
                            f'[AUTH] {account_name}: Login successful via {path} ({request_mode})'
                        )
                        return True, ''

                    if response.status_code in (200, 201):
                        try:
                            result = response.json()
                        except json.JSONDecodeError:
                            result = {}

                        token = _extract_session_token(result) if isinstance(
                            result, dict) else ''
                        if token:
                            client.cookies.set('session', token)
                            print(
                                f'[AUTH] {account_name}: Login successful, session token obtained'
                            )
                            return True, ''

                        success_flag = bool(
                            result.get('success')) if isinstance(
                                result, dict) else False
                        if success_flag and client.cookies.get('session'):
                            print(
                                f'[AUTH] {account_name}: Login successful with session cookie'
                            )
                            return True, ''

                        message = result.get('message') if isinstance(
                            result, dict) else None
                        last_error = (
                            f'{path} [{request_mode}] - '
                            f'{message or f"HTTP {response.status_code} (no token/session returned)"}'
                        )
                    else:
                        last_error = f'{path} [{request_mode}] - HTTP {response.status_code}'
                except Exception as e:
                    last_error = f'{path} [{request_mode}] - {str(e)}'

    print(f'[FAILED] {account_name}: Login failed - {last_error}')
    return False, last_error


def get_user_info(client, headers, user_info_url: str):
    """获取用户信息"""
    try:
        response = client.get(user_info_url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                user_data = data.get('data', {})
                quota = round(user_data.get('quota', 0) / 500000, 2)
                used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
                return {
                    'success':
                    True,
                    'quota':
                    quota,
                    'used_quota':
                    used_quota,
                    'display':
                    f':money: Current balance: ${quota}, Used: ${used_quota}',
                }
        content_type = response.headers.get('content-type', 'unknown')
        body_preview = response.text[:120].replace('\n',
                                                   ' ').replace('\r', ' ')
        return {
            'success':
            False,
            'error': (f'Failed to get user info: HTTP {response.status_code}, '
                      f'content-type={content_type}, body={body_preview}')
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to get user info: {str(e)[:50]}...'
        }


async def prepare_cookies(account_name: str, provider_config,
                          user_cookies: dict) -> dict | None:
    """准备请求所需的 cookies（可能包含 WAF cookies）"""
    waf_cookies = {}

    if provider_config.needs_waf_cookies():
        login_url = f'{provider_config.domain}{provider_config.login_path}'
        waf_cookies = await get_waf_cookies_with_playwright(
            account_name, login_url, provider_config.waf_cookie_names)
        if not waf_cookies:
            print(f'[FAILED] {account_name}: Unable to get WAF cookies')
            return None
    else:
        print(
            f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly'
        )

    return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config,
                     headers: dict):
    """执行签到请求"""
    print(f'[NETWORK] {account_name}: Executing check-in')

    checkin_headers = headers.copy()
    checkin_headers.update({
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
    })

    # 替换路径中的动态参数（如 {month}）
    sign_in_path = provider_config.sign_in_path.format(
        month=datetime.now().strftime('%Y-%m'))
    sign_in_url = f'{provider_config.domain}{sign_in_path}'

    if provider_config.check_in_method == 'GET':
        response = client.get(sign_in_url, headers=checkin_headers, timeout=30)
    else:
        response = client.post(sign_in_url,
                               headers=checkin_headers,
                               timeout=30)

    print(
        f'[RESPONSE] {account_name}: Response status code {response.status_code}'
    )

    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('ret') == 1 or result.get('code') == 0 or result.get(
                    'success'):
                print(f'[SUCCESS] {account_name}: Check-in successful!')
                return True
            else:
                error_msg = result.get('msg',
                                       result.get('message', 'Unknown error'))
                # 检查是否是"已经签到过"的情况，这种情况也算成功
                already_checked_keywords = [
                    '已经签到', '已签到', '重复签到', 'already checked', 'already signed'
                ]
                if any(keyword in error_msg.lower()
                       for keyword in already_checked_keywords):
                    print(
                        f'[SUCCESS] {account_name}: Already checked in today')
                    return True
                print(
                    f'[FAILED] {account_name}: Check-in failed - {error_msg}')
                print(
                    f'[DEBUG] {account_name}: Response body: {response.text[:200]}'
                )
                return False
        except json.JSONDecodeError:
            # 如果不是 JSON 响应，检查是否包含成功标识
            if 'success' in response.text.lower():
                print(f'[SUCCESS] {account_name}: Check-in successful!')
                return True
            else:
                print(
                    f'[FAILED] {account_name}: Check-in failed - Invalid response format'
                )
                print(
                    f'[DEBUG] {account_name}: Response body: {response.text[:200]}'
                )
                return False
    else:
        print(
            f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}'
        )
        print(f'[DEBUG] {account_name}: Response body: {response.text[:200]}')
        return False


def format_check_in_notification(detail: dict) -> str:
    """格式化签到通知消息

	Args:
		detail: 包含签到详情的字典

	Returns:
		格式化后的通知消息
	"""
    lines = [
        f'[签到] {detail["name"]}',
        f'  💵 余额: ${detail["after_quota"]:.2f}  |  📊 累计消耗: ${detail["after_used"]:.2f}',
    ]

    # 判断是否有变化
    has_reward = detail['check_in_reward'] != 0
    has_usage = detail['usage_increase'] != 0

    if has_reward or has_usage:
        # 已签到但期间有使用
        if not has_reward and has_usage:
            lines.append('  ℹ️  今日已签到（期间有使用）')

        # 签到获得
        if has_reward:
            lines.append(f'  🎁 签到获得: +${detail["check_in_reward"]:.2f}')
    else:
        # 无任何变化
        lines.append('  ℹ️  今日已签到，无变化')

    return '\n'.join(lines)


async def check_in_account(account: AccountConfig, account_index: int,
                           app_config: AppConfig):
    """为单个账号执行签到操作"""
    account_name = account.get_display_name(account_index)
    print(f'\n[PROCESSING] Starting to process {account_name}')

    provider_config = app_config.get_provider(account.provider)
    if not provider_config:
        print(
            f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration'
        )
        return False, None, None

    print(
        f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})'
    )

    # 确定认证方式（优先级：access_token > username/password > cookies）
    if account.has_access_token():
        print(f'[AUTH] {account_name}: Using access token authentication')
    elif account.has_credentials():
        print(f'[AUTH] {account_name}: Using username/password authentication')
    elif account.has_cookies():
        print(f'[AUTH] {account_name}: Using cookie authentication')
    else:
        print(
            f'[FAILED] {account_name}: No valid authentication method configured'
        )
        return False, None, None

    # WAF 场景：无论 token/账号密码/cookies，都先预置 WAF cookies
    if provider_config.needs_waf_cookies():
        user_cookies = parse_cookies(
            account.cookies) if account.has_cookies() else {}
        all_cookies = await prepare_cookies(account_name, provider_config,
                                            user_cookies)
        if not all_cookies:
            return False, None, None
    elif account.has_cookies(
    ) and not account.has_access_token() and not account.has_credentials():
        all_cookies = parse_cookies(account.cookies)
    else:
        all_cookies = {}

    client = httpx.Client(http2=True, timeout=30.0)

    try:
        if all_cookies:
            client.cookies.update(all_cookies)

        headers = {
            'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Referer': provider_config.domain,
            'Origin': provider_config.domain,
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            provider_config.api_user_key: account.api_user,
        }

        # 应用认证
        if account.has_access_token():
            # 访问令牌可能是 API Token，不一定适用于面板 session，做多方式兼容
            apply_access_token_auth(client, headers, account.access_token
                                    or '')
        elif account.has_credentials():
            # 使用用户名密码登录获取会话
            success, reason = login_with_credentials(client, account_name,
                                                     provider_config,
                                                     account.username or '',
                                                     account.password or '')
            if not success:
                print(
                    f'[FAILED] {account_name}: credential login failed - {reason}'
                )
                return False, None, {
                    'success': False,
                    'error': f'Credential login failed: {reason}'
                }
        else:
            # cookie 已在上方统一处理
            pass

        user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
        user_info_before = get_user_info(client, headers, user_info_url)
        if user_info_before and user_info_before.get('success'):
            print(user_info_before['display'])
        elif user_info_before:
            print(user_info_before.get('error', 'Unknown error'))

        if not user_info_before or not user_info_before.get('success'):
            if account.has_access_token():
                print(
                    f'[AUTH] {account_name}: Access token did not work for panel API, fallback to cookie if provided'
                )

                if account.has_credentials():
                    print(
                        f'[AUTH] {account_name}: Trying credential login as fallback...'
                    )
                    credential_ok, reason = login_with_credentials(
                        client, account_name, provider_config, account.username
                        or '', account.password or '')
                    if credential_ok:
                        user_info_before = get_user_info(
                            client, headers, user_info_url)
                    else:
                        print(
                            f'[AUTH] {account_name}: Credential fallback failed - {reason}'
                        )

                if account.has_cookies():
                    fallback_cookies = parse_cookies(account.cookies)
                    if fallback_cookies:
                        client.cookies.update(fallback_cookies)
                        user_info_before = get_user_info(
                            client, headers, user_info_url)
            if not user_info_before or not user_info_before.get('success'):
                return False, user_info_before, user_info_before

        if provider_config.needs_manual_check_in():
            success = execute_check_in(client, account_name, provider_config,
                                       headers)
            # 签到后再次获取用户信息，用于计算签到收益
            user_info_after = get_user_info(client, headers, user_info_url)
            return success, user_info_before, user_info_after
        else:
            print(
                f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)'
            )
            # 自动签到的情况，再次获取用户信息
            user_info_after = get_user_info(client, headers, user_info_url)
            return True, user_info_before, user_info_after

    except Exception as e:
        print(
            f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...'
        )
        return False, None, None
    finally:
        client.close()


async def main():
    """主函数"""
    print(
        '[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)'
    )
    print(
        f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
    )

    app_config = AppConfig.load_from_env()
    print(
        f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

    accounts = load_accounts_config()
    if not accounts:
        print('[FAILED] Unable to load account configuration, program exits')
        sys.exit(1)

    print(f'[INFO] Found {len(accounts)} account configurations')

    last_balance_hash = load_balance_hash()

    success_count = 0
    total_count = len(accounts)
    notification_content = []
    current_balances = {}
    account_check_in_details = {}  # 存储每个账号的签到详情
    need_notify = False  # 是否需要发送通知
    balance_changed = False  # 余额是否有变化

    for i, account in enumerate(accounts):
        account_key = f'account_{i + 1}'
        try:
            success, user_info_before, user_info_after = await check_in_account(
                account, i, app_config)
            if success:
                success_count += 1

            should_notify_this_account = False

            if not success:
                should_notify_this_account = True
                need_notify = True
                account_name = account.get_display_name(i)
                print(
                    f'[NOTIFY] {account_name} failed, will send notification')

            # 存储签到前后的余额信息
            if user_info_after and user_info_after.get('success'):
                current_quota = user_info_after['quota']
                current_used = user_info_after['used_quota']
                current_balances[account_key] = {
                    'quota': current_quota,
                    'used': current_used
                }

                # 计算签到收益
                if user_info_before and user_info_before.get('success'):
                    before_quota = user_info_before['quota']
                    before_used = user_info_before['used_quota']
                    after_quota = user_info_after['quota']
                    after_used = user_info_after['used_quota']

                    # 计算总额度（余额 + 历史消耗）
                    total_before = before_quota + before_used
                    total_after = after_quota + after_used

                    # 签到获得的额度 = 总额度增加量
                    check_in_reward = total_after - total_before

                    # 本次消耗 = 历史消耗增加量
                    usage_increase = after_used - before_used

                    # 余额变化
                    balance_change = after_quota - before_quota

                    account_check_in_details[account_key] = {
                        'name': account.get_display_name(i),
                        'before_quota': before_quota,
                        'before_used': before_used,
                        'after_quota': after_quota,
                        'after_used': after_used,
                        'check_in_reward': check_in_reward,  # 签到获得
                        'usage_increase': usage_increase,  # 本次消耗
                        'balance_change': balance_change,  # 余额变化
                        'success': success,
                    }

            if should_notify_this_account:
                account_name = account.get_display_name(i)
                status = '[SUCCESS]' if success else '[FAIL]'
                account_result = f'{status} {account_name}'
                if user_info_after and user_info_after.get('success'):
                    account_result += f'\n{user_info_after["display"]}'
                elif user_info_after:
                    account_result += f'\n{user_info_after.get("error", "Unknown error")}'
                notification_content.append(account_result)

        except Exception as e:
            account_name = account.get_display_name(i)
            print(f'[FAILED] {account_name} processing exception: {e}')
            need_notify = True  # 异常也需要通知
            notification_content.append(
                f'[FAIL] {account_name} exception: {str(e)[:50]}...')

    # 检查余额变化
    current_balance_hash = generate_balance_hash(
        current_balances) if current_balances else None
    if current_balance_hash:
        if last_balance_hash is None:
            # 首次运行
            balance_changed = True
            need_notify = True
            print(
                '[NOTIFY] First run detected, will send notification with current balances'
            )
        elif current_balance_hash != last_balance_hash:
            # 余额有变化
            balance_changed = True
            need_notify = True
            print('[NOTIFY] Balance changes detected, will send notification')
        else:
            print('[INFO] No balance changes detected')

    # 为有余额变化的情况添加所有成功账号到通知内容
    if balance_changed:
        for i, account in enumerate(accounts):
            account_key = f'account_{i + 1}'
            if account_key in account_check_in_details:
                detail = account_check_in_details[account_key]
                account_name = detail['name']

                # 使用格式化函数生成通知消息
                account_result = format_check_in_notification(detail)

                # 检查是否已经在通知内容中（避免重复）
                if not any(account_name in item
                           for item in notification_content):
                    notification_content.append(account_result)

    # 保存当前余额hash
    if current_balance_hash:
        save_balance_hash(current_balance_hash)

    if need_notify and notification_content:
        # 构建通知内容
        summary = [
            '[统计] 签到结果统计:',
            f'[成功] 成功: {success_count}/{total_count}',
            f'[失败] 失败: {total_count - success_count}/{total_count}',
        ]

        if success_count == total_count:
            summary.append('[成功] 所有账号签到成功！')
        elif success_count > 0:
            summary.append('[警告] 部分账号签到成功')
        else:
            summary.append('[错误] 所有账号签到失败')

        time_info = f'[时间] 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

        notify_content = '\n\n'.join([
            time_info, '\n━━━━━━━━━━━━━━━━━━━━\n'.join(notification_content),
            '\n'.join(summary)
        ])

        print(notify_content)
        notify_title = f'New api签到({success_count}/{total_count})'
        notify.push_message(notify_title, notify_content, msg_type='text')
        print('[NOTIFY] Notification sent due to failures or balance changes')
    else:
        print(
            '[INFO] All accounts successful and no balance changes detected, notification skipped'
        )

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[WARNING] Program interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'\n[FAILED] Error occurred during program execution: {e}')
        sys.exit(1)


if __name__ == '__main__':
    run_main()
