"use client"

import { useState, useEffect } from "react"
import {
  Shield,
  Scan,
  Server,
  AlertTriangle,
  CheckCircle,
  Clock,
  Target,
  Settings,
  Download,
  Play,
  Pause,
  Lock,
  Globe,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Textarea } from "@/components/ui/textarea"

// 타입 정의
interface ScanResult {
  ip: string
  port: number
  status: string
  service?: string
  version?: string
  vulnerability?: string
  timestamp: string
}

interface AttackResult {
  type: "ssh" | "web"
  target: string
  success: boolean
  credentials?: {
    username: string
    password: string
  }
  message: string
  timestamp: string
}

interface AssetInfo {
  id: number
  ip: string
  hostname: string
  os: string
  status: string
  last_scanned: string
  ports: Array<{
    port: number
    protocol: string
    state: string
    service: string
    product: string
    version: string
    scripts?: Record<string, string>
  }>
}

export default function PortScannerDashboard() {
  // 상태 관리
  const [startPort, setStartPort] = useState("");
  const [endPort, setEndPort] = useState("")
  const [targetIp, setTargetIp] = useState("")
  const [scanType, setScanType] = useState("quick")
  const [timingProfile, setTimingProfile] = useState("normal")
  const [isScanning, setIsScanning] = useState(false)
  const [isAttacking, setIsAttacking] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [attackResults, setAttackResults] = useState<AttackResult[]>([])
  const [assets, setAssets] = useState<AssetInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // API 기본 URL (asm.exe 연동으로 변경)
  const ASM_API_BASE = "http://localhost:8080/api"
  const FLASK_API_BASE = "http://localhost:5001"

  // 초기 데이터 로드 (asm.exe에서)
  useEffect(() => {
    loadAssets()
  }, [])

  // 자산 목록 로드 (asm.exe에서)
  const loadAssets = async () => {
    try {
      const response = await fetch(`${ASM_API_BASE}/assets`)
      if (response.ok) {
        const data = await response.json()
        setAssets(data)
      }
    } catch (error) {
      console.error("자산 로드 실패:", error)
    }
  }

  // 포트 스캔 실행 (asm.exe 연동)
  const handleScan = async () => {
    if (!targetIp.trim()) {
      setError("대상 IP/도메인을 입력해주세요")
      return
    }

    setIsScanning(true)
    setScanProgress(0)
    setError(null)
    setScanResults([])

    try {
      // asm.exe에 스캔 요청
      const nmap_args = getNmapArguments()
      const scanResponse = await fetch(`${ASM_API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetIp,
          arguments: nmap_args
        }),
      })

      if (!scanResponse.ok) {
        throw new Error(`스캔 요청 실패: ${scanResponse.status}`)
      }

      // 진행률 시뮬레이션
      const progressInterval = setInterval(() => {
        setScanProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 10
        })
      }, 500)

      // 결과 폴링 (asm.exe의 /api/assets에서 조회)
      setTimeout(async () => {
        try {
          const resultsResponse = await fetch(`${ASM_API_BASE}/assets`)
          if (resultsResponse.ok) {
            const assets = await resultsResponse.json()
            
            // 타겟 IP에 해당하는 자산 찾기
            const targetAsset = assets.find((asset: any) => 
              asset.ip === targetIp || asset.hostname === targetIp
            )

            if (targetAsset && targetAsset.ports) {
              // asm.exe 결과를 기존 형식으로 변환
              const results: ScanResult[] = targetAsset.ports.map((port: any) => ({
                ip: targetAsset.ip,
                port: port.port,
                status: port.state,
                service: port.service || "Unknown",
                version: port.version || "",
                vulnerability: port.scripts && Object.keys(port.scripts).length > 0 ? "medium" : "low",
                timestamp: targetAsset.last_scanned
              }))

              setScanResults(results)
              setAssets(assets)
            }
          }
          setScanProgress(100)
        } catch (error) {
          console.error("결과 조회 실패:", error)
        }
        setIsScanning(false)
        clearInterval(progressInterval)
      }, 3000)
    } catch (error) {
      setError(`스캔 실패: ${error instanceof Error ? error.message : "알 수 없는 오류"}`)
      setIsScanning(false)
    }
  }

  // Nmap 인수 생성
  const getNmapArguments = () => {
    let args = "-sV"
    if (scanType === "comprehensive") {
      args = "-sV -O --script=\"vuln,http-enum,http-sql-injection\""
    } else if (scanType === "stealth") {
      args = "-sS -sV"
    }
    if (startPort && endPort) {
      args += ` -p ${startPort}-${endPort}`
    }
    return args
  }

  // SSH 브루트포스 공격 (Flask 서버 사용)
  const handleSSHAttack = async () => {
    if (!targetIp.trim()) {
      setError("대상을 먼저 설정해주세요")
      return
    }

    setIsAttacking(true)
    setError(null)

    try {
      const response = await fetch(`${FLASK_API_BASE}/attack/ssh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: targetIp,
          port: 22,
          username: "testuser",
          passwords: ["pass123", "password", "admin", "123456"],
        }),
      })

      if (!response.ok) {
        throw new Error(`SSH 공격 실패: ${response.status}`)
      }

      const result = await response.json()
      const attackResult: AttackResult = {
        type: "ssh",
        target: `${targetIp}:22`,
        success: result.success,
        credentials: result.credentials,
        message: result.message || (result.success ? "SSH 로그인 성공" : "SSH 로그인 실패"),
        timestamp: new Date().toISOString(),
      }

      setAttackResults((prev) => [attackResult, ...prev])
    } catch (error) {
      setError(`SSH 공격 실패: ${error instanceof Error ? error.message : "알 수 없는 오류"}`)
    } finally {
      setIsAttacking(false)
    }
  }

  // 웹 브루트포스 공격 (Flask 서버 사용)
  const handleWebAttack = async () => {
    if (!targetIp.trim()) {
      setError("대상을 먼저 설정해주세요")
      return
    }

    setIsAttacking(true)
    setError(null)

    try {
      const response = await fetch(`${FLASK_API_BASE}/attack/web`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: `http://${targetIp}/dvwa/login.php`,
          brute_url: `http://${targetIp}/dvwa/vulnerabilities/brute/`,
          passwords: ["password", "admin", "123456", "root"],
        }),
      })

      if (!response.ok) {
        throw new Error(`웹 공격 실패: ${response.status}`)
      }

      const result = await response.json()
      const attackResult: AttackResult = {
        type: "web",
        target: `http://${targetIp}`,
        success: result.success,
        credentials: result.credentials,
        message: result.message || (result.success ? "웹 로그인 성공" : "웹 로그인 실패"),
        timestamp: new Date().toISOString(),
      }

      setAttackResults((prev) => [attackResult, ...prev])
    } catch (error) {
      setError(`웹 공격 실패: ${error instanceof Error ? error.message : "알 수 없는 오류"}`)
    } finally {
      setIsAttacking(false)
    }
  }

  // 포트 범위 파싱
  const parsePortRange = (): number[] => {
    const s = parseInt(startPort, 10)
    const e = parseInt(endPort, 10)
    if (isNaN(s) || isNaN(e) || s > e) return []
    return Array.from({ length: e - s + 1 }, (_, i) => s + i)
  }

  // 취약도 색상 결정
  const getVulnerabilityColor = (status: string, vulnerability: string) => {
    if (status !== "open") return "bg-gray-500"; // 닫힘이면 회색(불빛 없음)
    switch (vulnerability?.toLowerCase()) {
      case "critical": return "bg-red-600";
      case "high": return "bg-red-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-green-500";
      default: return "bg-gray-500";
    }
  }

  // 상태 아이콘 결정
  const getStatusIcon = (status: string) => {
    switch (status) {
      case "open":
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case "closed":
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      case "filtered":
        return <Clock className="h-4 w-4 text-yellow-500" />
      default:
        return <Scan className="h-4 w-4 text-gray-500" />
    }
  }

  // 결과 리포트 다운로드
  const downloadReport = () => {
    const report = {
      target: targetIp,
      scan_results: scanResults,
      attack_results: attackResults,
      timestamp: new Date().toISOString(),
    }

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `security-report-${targetIp}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-10 h-10 bg-blue-600 rounded-lg">
                <Shield className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold">포트 스캐너 프로</h1>
                <p className="text-sm text-slate-400">네트워크 보안 분석 도구</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Button
                variant="outline"
                size="sm"
                className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
              >
                <Settings className="w-4 h-4 mr-2" />
                설정
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={downloadReport}
                className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
              >
                <Download className="w-4 h-4 mr-2" />
                내보내기
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Error Display */}
      {error && (
        <div className="container mx-auto px-6 pt-4">
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <span className="text-red-400">{error}</span>
            </div>
          </div>
        </div>
      )}

      <div className="container mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Scan Configuration */}
          <div className="lg:col-span-1">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="flex items-center text-white">
                  <Target className="w-5 h-5 mr-2 text-blue-500" />
                  스캔 설정
                </CardTitle>
                <CardDescription className="text-slate-400">네트워크 스캔 매개변수를 설정하세요</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="target" className="text-white">
                    대상 IP/도메인
                  </Label>
                  <Input
                    id="target"
                    placeholder="192.168.1.1 또는 example.com"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                    className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="start-port" className="text-white">
                      시작 포트
                    </Label>
                    <Input
                      id="start-port"
                      placeholder="1"
                      value={startPort}
                      onChange={e => {
                        const val = e.target.value;
                        if (/^\d*$/.test(val)) setStartPort(val);
                      }}
                      className="bg-slate-800 border-slate-700 text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="end-port" className="text-white">
                      끝 포트
                    </Label>
                    <Input
                      id="end-port"
                      placeholder="65535"
                      value={endPort}
                      onChange={e => {
                        const val = e.target.value;
                        if (/^\d*$/.test(val)) setEndPort(val);
                      }}
                      className="bg-slate-800 border-slate-700 text-white"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="scan-type" className="text-white">
                    스캔 유형
                  </Label>
                  <Select value={scanType} onValueChange={setScanType}>
                    <SelectTrigger className="bg-slate-800 border-slate-700 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-700">
                      <SelectItem value="quick">빠른 스캔</SelectItem>
                      <SelectItem value="comprehensive">포괄적 스캔</SelectItem>
                      <SelectItem value="stealth">스텔스 스캔</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="timing" className="text-white">
                    타이밍 템플릿
                  </Label>
                  <Select value={timingProfile} onValueChange={setTimingProfile}>
                    <SelectTrigger className="bg-slate-800 border-slate-700 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-700">
                      <SelectItem value="paranoid">편집증적 (가장 느림)</SelectItem>
                      <SelectItem value="sneaky">은밀함</SelectItem>
                      <SelectItem value="polite">예의 바름</SelectItem>
                      <SelectItem value="normal">보통</SelectItem>
                      <SelectItem value="aggressive">공격적</SelectItem>
                      <SelectItem value="insane">광적 (가장 빠름)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button
                  onClick={handleScan}
                  disabled={isScanning || isAttacking}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                >
                  {isScanning ? (
                    <>
                      <Pause className="w-4 h-4 mr-2" />
                      스캔 중...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 mr-2" />
                      스캔 시작
                    </>
                  )}
                </Button>

                {isScanning && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">진행률</span>
                      <span className="text-white">{scanProgress}%</span>
                    </div>
                    <Progress value={scanProgress} className="bg-slate-800" />
                  </div>
                )}

                {/* Attack Buttons */}
                <div className="space-y-3 pt-4 border-t border-slate-700">
                  <Label className="text-white font-medium">공격 도구</Label>
                  <div className="grid grid-cols-1 gap-2">
                    <Button
                      variant="destructive"
                      onClick={handleSSHAttack}
                      disabled={isScanning || isAttacking}
                      className="w-full"
                    >
                      <Lock className="mr-2 h-4 w-4" />
                      SSH 브루트포스
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={handleWebAttack}
                      disabled={isScanning || isAttacking}
                      className="w-full"
                    >
                      <Globe className="mr-2 h-4 w-4" />
                      웹 브루트포스
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results */}
          <div className="lg:col-span-2">
            <Tabs defaultValue="results" className="space-y-6">
              <TabsList className="bg-slate-800 border-slate-700">
                <TabsTrigger value="results" className="data-[state=active]:bg-slate-700 text-white">
                  포트 스캔 결과
                </TabsTrigger>
                <TabsTrigger value="attacks" className="data-[state=active]:bg-slate-700 text-white">
                  공격 결과
                </TabsTrigger>
                <TabsTrigger value="assets" className="data-[state=active]:bg-slate-700 text-white">
                  자산 관리
                </TabsTrigger>
                <TabsTrigger value="logs" className="data-[state=active]:bg-slate-700 text-white">
                  로그
                </TabsTrigger>
              </TabsList>

              <TabsContent value="results">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between text-white">
                      <div className="flex items-center">
                        <Scan className="w-5 h-5 mr-2 text-green-500" />
                        포트 스캔 결과
                      </div>
                      <Badge variant="outline" className="bg-slate-800 text-white border-slate-700">
                        {scanResults.length} 포트 발견
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {scanResults.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">
                        스캔 결과가 없습니다. 먼저 스캔을 실행해주세요.
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {scanResults.map((result, index) => (
                          <div
                            key={index}
                            className="flex items-center justify-between p-4 bg-slate-800 rounded-lg border border-slate-700"
                          >
                            <div className="flex items-center space-x-4">
                              {getStatusIcon(result.status)}
                              <div>
                                <div className="flex items-center space-x-2">
                                  <span className="font-mono text-lg text-white">{result.port}</span>
                                  <Badge variant="outline" className="bg-slate-700 text-white border-slate-600">
                                    {result.service || "Unknown"}
                                  </Badge>
                                </div>
                                <p className="text-sm text-slate-400">
                                  {result.version || "Version unknown"} • {result.ip}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center space-x-3">
                              <Badge variant="outline" className="bg-slate-700 text-white border-slate-600">
                                {result.status === "open" ? "열림" : "닫힘"}
                              </Badge>
                              <div
                                className={`w-3 h-3 rounded-full ${getVulnerabilityColor(result.status, result.vulnerability || "low")}`}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="attacks">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Lock className="w-5 h-5 mr-2 text-red-500" />
                      공격 결과
                    </CardTitle>
                    <CardDescription className="text-slate-400">SSH 및 웹 브루트포스 공격 결과</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {attackResults.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">공격 결과가 없습니다.</div>
                    ) : (
                      <div className="space-y-4">
                        {attackResults.map((result, index) => (
                          <div
                            key={index}
                            className={`p-4 rounded-lg border ${
                              result.success ? "bg-green-900/20 border-green-500/30" : "bg-red-900/20 border-red-500/30"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-semibold text-white">
                                  {result.type.toUpperCase()} 공격 - {result.target}
                                </div>
                                <div className="text-sm text-slate-400">{result.message}</div>
                                {result.credentials && (
                                  <div className="text-sm mt-2">
                                    <span className="text-green-400">
                                      발견된 인증정보: {result.credentials.username}/{result.credentials.password}
                                    </span>
                                  </div>
                                )}
                              </div>
                              <Badge className={result.success ? "bg-green-600" : "bg-red-600"}>
                                {result.success ? "성공" : "실패"}
                              </Badge>
                            </div>
                            <div className="text-xs text-slate-500 mt-2">
                              {new Date(result.timestamp).toLocaleString()}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="assets">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Server className="w-5 h-5 mr-2 text-blue-500" />
                      자산 관리
                    </CardTitle>
                    <CardDescription className="text-slate-400">스캔된 자산 및 서비스 정보</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {assets.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">등록된 자산이 없습니다.</div>
                    ) : (
                      <div className="space-y-4">
                        {assets.map((asset, index) => (
                          <div key={index} className="p-4 bg-slate-800 rounded-lg border border-slate-700">
                            <div className="flex items-center justify-between mb-3">
                              <div>
                                <div className="font-semibold text-white">{asset.ip}</div>
                                <div className="text-sm text-slate-400">
                                  {asset.hostname} • {asset.os}
                                </div>
                              </div>
                              <Badge className={asset.status === "up" ? "bg-green-600" : "bg-red-600"}>
                                {asset.status}
                              </Badge>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                              {asset.ports.map((port, portIndex) => (
                                <div key={portIndex} className="text-sm p-2 bg-slate-700 rounded">
                                  <span className="font-medium text-white">{port.port}</span> - {port.service}
                                  {port.version && <div className="text-xs text-slate-400">{port.version}</div>}
                                </div>
                              ))}
                            </div>
                            <div className="text-xs text-slate-500 mt-2">
                              마지막 스캔: {new Date(asset.last_scanned).toLocaleString()}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="logs">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Server className="w-5 h-5 mr-2 text-blue-500" />
                      스캔 로그
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Textarea
                      readOnly
                      value={`[${new Date().toLocaleString()}] 대상에서 포트 스캔 시작: ${targetIp || "미설정"}
[${new Date().toLocaleString()}] 스캔 유형: ${scanType}
[${new Date().toLocaleString()}] 포트 범위: ${startPort}-${endPort}
[${new Date().toLocaleString()}] 타이밍 프로필: ${timingProfile}
${scanResults
  .map(
    (result) =>
      `[${new Date(result.timestamp).toLocaleString()}] 포트 ${result.port}/${result.service} ${result.status} ${result.version || ""}`,
  )
  .join("\n")}
${attackResults
  .map(
    (result) =>
      `[${new Date(result.timestamp).toLocaleString()}] ${result.type.toUpperCase()} 공격 ${result.target}: ${result.success ? "성공" : "실패"} - ${result.message}`,
  )
  .join("\n")}

[${new Date().toLocaleString()}] 스캔 완료. ${scanResults.length}개 포트 스캔됨`}
                      className="min-h-[300px] bg-slate-800 border-slate-700 text-green-400 font-mono text-sm"
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </div>
    </div>
  )
}
