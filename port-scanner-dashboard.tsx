"use client";

import { useState, useEffect, useCallback } from "react";
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
  Trash2,
  Bug,
  TrendingUp,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";

// 타입 정의
interface ScanResult {
  ip: string;
  port: number;
  status: string;
  service?: string;
  version?: string;
  vulnerability?: string;
  timestamp: string;
  cve?: string[];
  cvss_score?: number;
  risk_level?: "critical" | "high" | "medium" | "low";
}

interface AttackResult {
  type: "ssh" | "web";
  target: string;
  success: boolean;
  credentials?: {
    username: string;
    password: string;
  };
  message: string;
  timestamp: string;
}

interface AssetInfo {
  id: number;
  ip: string;
  hostname: string;
  os: string;
  status: string;
  last_scanned: string;
  risk_score?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service: string;
    product: string;
    version: string;
    scripts?: Record<string, string>;
    cve?: string[];
    cvss_score?: number;
    risk_level?: "critical" | "high" | "medium" | "low";
  }>;
}

interface VulnerabilityInfo {
  cve: string;
  cvss_score: number;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  service: string;
  port: number;
  ip: string;
  published_date: string;
}

// OSV.dev API로 취약점 조회
async function fetchOsvVulns(
  service: string,
  version: string,
  ecosystem: string = "Debian"
) {
  try {
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: service, ecosystem },
        version: version,
      }),
    });
    if (!response.ok) return [];
    const data = await response.json();
    return data.vulns || [];
  } catch {
    return [];
  }
}

export default function PortScannerDashboard() {
  // 상태 관리
  const [startPort, setStartPort] = useState("");
  const [endPort, setEndPort] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [timingProfile, setTimingProfile] = useState("normal");
  const [isScanning, setIsScanning] = useState(false);
  const [isAttacking, setIsAttacking] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [attackResults, setAttackResults] = useState<AttackResult[]>([]);
  const [assets, setAssets] = useState<AssetInfo[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityInfo[]>(
    []
  );
  const [error, setError] = useState<string | null>(null);

  // *** 여기를 Flask 통합 서버로 교체 ***
  const API_BASE = "http://localhost:8080/api";

  // 초기 데이터 로드
  useEffect(() => {
    loadAssets();
    loadVulnerabilities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 자산 목록 로드
  const loadAssets = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/assets`);
      if (response.ok) {
        let data = await response.json();
        if (!Array.isArray(data)) data = [];

        const assetsWithRisk = data.map((asset: AssetInfo) => {
          const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };

          asset.ports.forEach((port) => {
            if (port.risk_level) {
              riskCounts[port.risk_level]++;
            }
          });

          const riskScore =
            riskCounts.critical * 10 +
            riskCounts.high * 7 +
            riskCounts.medium * 4 +
            riskCounts.low * 1;

          return {
            ...asset,
            risk_score: riskScore,
            critical_count: riskCounts.critical,
            high_count: riskCounts.high,
            medium_count: riskCounts.medium,
            low_count: riskCounts.low,
          };
        });

        setAssets(assetsWithRisk);
      } else {
        setAssets([]);
      }
    } catch (err) {
      console.error("자산 로드 실패:", err);
      setAssets([]);
    }
  }, [API_BASE]);

  // 취약점 데이터 로드
  const loadVulnerabilities = useCallback(() => {
    if (scanResults.length > 0) {
      const vulns: VulnerabilityInfo[] = [];
      scanResults.forEach((result) => {
        if (result.cve && result.cve.length > 0) {
          result.cve.forEach((cveId) => {
            vulns.push({
              cve: cveId,
              cvss_score: result.cvss_score || 0,
              severity: result.risk_level || "low",
              description: "",
              service: result.service || "",
              port: result.port,
              ip: result.ip,
              published_date: "",
            });
          });
        }
      });
      setVulnerabilities(vulns);
    }
  }, [scanResults]);

  // 스캔 타입 → Flask 서버 method 매핑 함수
  const scanTypeToMethod = (type: string) => {
    switch (type) {
      case "quick":
        return "nmap";
      case "stealth":
        return "syn";
      case "tcp":
        return "tcp";
      case "ack":
        return "ack";
      case "udp":
        return "udp";
      case "comprehensive":
        return "nmap";
      default:
        return "nmap";
    }
  };

  // 포트 스캔 실행
  const handleScan = async () => {
    if (!targetIp.trim()) {
      setError("대상 IP/도메인을 입력해주세요");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setError(null);
    setScanResults([]);
    setVulnerabilities([]);

    try {
      const scanResponse = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetIp,
          ports: startPort && endPort ? `${startPort}-${endPort}` : "20-80",
          method: scanTypeToMethod(scanType),
        }),
      });

      if (!scanResponse.ok) {
        throw new Error(`스캔 요청 실패: ${scanResponse.status}`);
      }

      const progressInterval = setInterval(() => {
        setScanProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 500);

      setTimeout(async () => {
        try {
          const resultsResponse = await fetch(`${API_BASE}/assets`);
          if (resultsResponse.ok) {
            let assetsResp = await resultsResponse.json();
            if (!Array.isArray(assetsResp)) assetsResp = [];
            setAssets(assetsResp);

            const targetAsset = assetsResp.find(
              (asset: AssetInfo) =>
                asset.ip === targetIp || asset.hostname === targetIp
            );
            if (targetAsset && Array.isArray(targetAsset.ports)) {
              const results: ScanResult[] = await Promise.all(
                targetAsset.ports.map(async (port) => {
                  let cveList: string[] = [];
                  let cvssScore = 0;
                  let riskLevel: "critical" | "high" | "medium" | "low" = "low";
                  let osvVulns: any[] = [];
                  if (port.service && port.version) {
                    osvVulns = await fetchOsvVulns(
                      port.service,
                      port.version,
                      "Debian"
                    );
                    cveList = osvVulns.map(
                      (v: any) => v.id || v.aliases?.[0] || ""
                    );
                    if (
                      osvVulns.length > 0 &&
                      osvVulns[0].severity?.length > 0
                    ) {
                      const cvss = osvVulns[0].severity.find(
                        (s: any) => s.type === "CVSS_V3"
                      );
                      if (cvss) {
                        cvssScore = parseFloat(cvss.score);
                        if (cvssScore >= 9) riskLevel = "critical";
                        else if (cvssScore >= 7) riskLevel = "high";
                        else if (cvssScore >= 4) riskLevel = "medium";
                        else riskLevel = "low";
                      }
                    }
                  }

                  return {
                    ip: targetAsset.ip,
                    port: port.port,
                    status: port.state,
                    service: port.service || "Unknown",
                    version: port.version || "",
                    vulnerability: osvVulns.length > 0 ? riskLevel : "low",
                    timestamp: targetAsset.last_scanned,
                    cve: cveList,
                    cvss_score: cvssScore,
                    risk_level: riskLevel,
                  };
                })
              );
              setScanResults(results);

              // 취약점 데이터 업데이트
              const vulns: VulnerabilityInfo[] = [];
              results.forEach((result, idx) => {
                if (result.cve && result.cve.length > 0) {
                  result.cve.forEach((cveId) => {
                    vulns.push({
                      cve: cveId,
                      cvss_score: result.cvss_score || 0,
                      severity: result.risk_level || "low",
                      description: "",
                      service: result.service || "",
                      port: result.port,
                      ip: result.ip,
                      published_date: "",
                    });
                  });
                }
              });
              setVulnerabilities(vulns);
            } else {
              setScanResults([]);
            }
          } else {
            setAssets([]);
            setScanResults([]);
          }
          setScanProgress(100);
        } catch (err) {
          console.error("결과 조회 실패:", err);
          setScanResults([]);
        }
        setIsScanning(false);
        clearInterval(progressInterval);
      }, 3000);
    } catch (err) {
      setError(
        `스캔 실패: ${err instanceof Error ? err.message : "알 수 없는 오류"}`
      );
      setIsScanning(false);
    }
  };

  // SSH 브루트포스 공격
  const handleSSHAttack = async () => {
    if (!targetIp.trim()) {
      setError("대상을 먼저 설정해주세요");
      return;
    }

    setIsAttacking(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/attack/ssh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: targetIp,
          port: 22,
          username: "testuser",
          passwords: ["pass123", "password", "admin", "123456"],
        }),
      });

      if (!response.ok) {
        throw new Error(`SSH 공격 실패: ${response.status}`);
      }

      const result = await response.json();
      const attackResult: AttackResult = {
        type: "ssh",
        target: `${targetIp}:22`,
        success: result.success,
        credentials: result.credentials,
        message:
          result.message ||
          (result.success ? "SSH 로그인 성공" : "SSH 로그인 실패"),
        timestamp: new Date().toISOString(),
      };
      setAttackResults((prev) => [attackResult, ...prev]);
    } catch (err) {
      setError(
        `SSH 공격 실패: ${
          err instanceof Error ? err.message : "알 수 없는 오류"
        }`
      );
    } finally {
      setIsAttacking(false);
    }
  };

  // 웹 브루트포스 공격
  const handleWebAttack = async () => {
    if (!targetIp.trim()) {
      setError("대상을 먼저 설정해주세요");
      return;
    }

    setIsAttacking(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/attack/web`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: `http://${targetIp}/dvwa/login.php`,
          brute_url: `http://${targetIp}/dvwa/vulnerabilities/brute/`,
          passwords: ["password", "admin", "123456", "root"],
        }),
      });

      if (!response.ok) {
        throw new Error(`웹 공격 실패: ${response.status}`);
      }

      const result = await response.json();
      const attackResult: AttackResult = {
        type: "web",
        target: `http://${targetIp}`,
        success: result.success,
        credentials: result.credentials,
        message:
          result.message ||
          (result.success ? "웹 로그인 성공" : "웹 로그인 실패"),
        timestamp: new Date().toISOString(),
      };

      setAttackResults((prev) => [attackResult, ...prev]);
    } catch (err) {
      setError(
        `웹 공격 실패: ${
          err instanceof Error ? err.message : "알 수 없는 오류"
        }`
      );
    } finally {
      setIsAttacking(false);
    }
  };

  // 포트 범위 파싱
  const parsePortRange = (): number[] => {
    const s = Number.parseInt(startPort, 10);
    const e = Number.parseInt(endPort, 10);
    if (isNaN(s) || isNaN(e) || s > e) return [];
    return Array.from({ length: e - s + 1 }, (_, i) => s + i);
  };

  // 취약도 색상 결정
  const getVulnerabilityColor = (status: string, vulnerability: string) => {
    if (status !== "open") return "bg-gray-500";
    switch (vulnerability?.toLowerCase()) {
      case "critical":
        return "bg-red-600";
      case "high":
        return "bg-red-500";
      case "medium":
        return "bg-yellow-500";
      case "low":
        return "bg-green-500";
      default:
        return "bg-gray-500";
    }
  };

  // CVSS 점수에 따른 색상
  const getCVSSColor = (score: number) => {
    if (score >= 9.0) return "text-red-600";
    if (score >= 7.0) return "text-red-500";
    if (score >= 4.0) return "text-yellow-500";
    return "text-green-500";
  };

  // 위험도 배지 색상
  const getRiskBadgeColor = (level: string) => {
    switch (level) {
      case "critical":
        return "bg-red-600";
      case "high":
        return "bg-red-500";
      case "medium":
        return "bg-yellow-500";
      case "low":
        return "bg-green-500";
      default:
        return "bg-gray-500";
    }
  };

  // 상태 아이콘 결정
  const getStatusIcon = (status: string) => {
    switch (status) {
      case "open":
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "closed":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case "filtered":
        return <Clock className="h-4 w-4 text-yellow-500" />;
      default:
        return <Scan className="h-4 w-4 text-gray-500" />;
    }
  };

  // 결과 리포트 다운로드
  const downloadReport = () => {
    const report = {
      target: targetIp,
      scan_results: scanResults,
      attack_results: attackResults,
      vulnerabilities: vulnerabilities,
      timestamp: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-report-${targetIp}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // 자산 삭제
  const handleDeleteAsset = async (assetId: number, assetIp: string) => {
    if (!confirm(`정말로 자산 ${assetIp}을(를) 삭제하시겠습니까?`)) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/assets/${assetId}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error(`자산 삭제 실패: ${response.status}`);
      }

      await loadAssets();
      setError(null);

      if (scanResults.some((result) => result.ip === assetIp)) {
        setScanResults([]);
      }
    } catch (err) {
      setError(
        `자산 삭제 실패: ${
          err instanceof Error ? err.message : "알 수 없는 오류"
        }`
      );
    }
  };

  // 전체 취약점 통계
  const getVulnerabilityStats = () => {
    const stats = { critical: 0, high: 0, medium: 0, low: 0 };
    vulnerabilities.forEach((vuln) => {
      stats[vuln.severity]++;
    });
    return stats;
  };

  const vulnStats = getVulnerabilityStats();

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
                <p className="text-sm text-slate-400">
                  네트워크 보안 분석 도구
                </p>
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

      {/* 취약점 요약 대시보드 */}
      {vulnerabilities.length > 0 && (
        <div className="container mx-auto px-6 py-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="bg-red-900/20 border-red-500/30">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-red-400">Critical</p>
                    <p className="text-2xl font-bold text-red-300">
                      {vulnStats.critical}
                    </p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-orange-900/20 border-orange-500/30">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-orange-400">High</p>
                    <p className="text-2xl font-bold text-orange-300">
                      {vulnStats.high}
                    </p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-yellow-900/20 border-yellow-500/30">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-yellow-400">Medium</p>
                    <p className="text-2xl font-bold text-yellow-300">
                      {vulnStats.medium}
                    </p>
                  </div>
                  <Eye className="h-8 w-8 text-yellow-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-green-900/20 border-green-500/30">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-green-400">Low</p>
                    <p className="text-2xl font-bold text-green-300">
                      {vulnStats.low}
                    </p>
                  </div>
                  <CheckCircle className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

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
                <CardDescription className="text-slate-400">
                  네트워크 스캔 매개변수를 설정하세요
                </CardDescription>
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
                      onChange={(e) => {
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
                      onChange={(e) => {
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
                  <Select
                    value={timingProfile}
                    onValueChange={setTimingProfile}
                  >
                    <SelectTrigger className="bg-slate-800 border-slate-700 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-700">
                      <SelectItem value="paranoid">
                        편집증적 (가장 느림)
                      </SelectItem>
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
                      <Globe className="mr-2 h-4 w-4" />웹 브루트포스
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
                <TabsTrigger
                  value="results"
                  className="data-[state=active]:bg-slate-700 text-white"
                >
                  포트 스캔 결과
                </TabsTrigger>
                <TabsTrigger
                  value="vulnerabilities"
                  className="data-[state=active]:bg-slate-700 text-white"
                >
                  취약점 분석
                </TabsTrigger>
                <TabsTrigger
                  value="attacks"
                  className="data-[state=active]:bg-slate-700 text-white"
                >
                  공격 결과
                </TabsTrigger>
                <TabsTrigger
                  value="assets"
                  className="data-[state=active]:bg-slate-700 text-white"
                >
                  자산 관리
                </TabsTrigger>
                <TabsTrigger
                  value="logs"
                  className="data-[state=active]:bg-slate-700 text-white"
                >
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
                      <Badge
                        variant="outline"
                        className="bg-slate-800 text-white border-slate-700"
                      >
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
                                  <span className="font-mono text-lg text-white">
                                    {result.port}
                                  </span>
                                  <Badge
                                    variant="outline"
                                    className="bg-slate-700 text-white border-slate-600"
                                  >
                                    {result.service || "Unknown"}
                                  </Badge>
                                  {result.cvss_score &&
                                    result.cvss_score > 0 && (
                                      <Badge
                                        className={`${getRiskBadgeColor(
                                          result.risk_level || "low"
                                        )} text-white`}
                                      >
                                        CVSS {result.cvss_score.toFixed(1)}
                                      </Badge>
                                    )}
                                </div>
                                <p className="text-sm text-slate-400">
                                  {result.version || "Version unknown"} •{" "}
                                  {result.ip}
                                </p>
                                {result.cve && result.cve.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {result.cve.map((cve, cveIndex) => (
                                      <Badge
                                        key={cveIndex}
                                        variant="outline"
                                        className="text-xs bg-red-900/20 border-red-500/30 text-red-400"
                                      >
                                        {cve}
                                      </Badge>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center space-x-3">
                              <Badge
                                variant="outline"
                                className="bg-slate-700 text-white border-slate-600"
                              >
                                {result.status === "open" ? "열림" : "닫힘"}
                              </Badge>
                              <div
                                className={`w-3 h-3 rounded-full ${getVulnerabilityColor(
                                  result.status,
                                  result.risk_level || "low"
                                )}`}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="vulnerabilities">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center text-white">
                      <Bug className="w-5 h-5 mr-2 text-red-500" />
                      취약점 분석
                    </CardTitle>
                    <CardDescription className="text-slate-400">
                      발견된 CVE 및 보안 취약점
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {vulnerabilities.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">
                        취약점이 발견되지 않았습니다.
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {vulnerabilities.map((vuln, index) => (
                          <div
                            key={index}
                            className={`p-4 rounded-lg border ${
                              vuln.severity === "critical"
                                ? "bg-red-900/20 border-red-500/30"
                                : vuln.severity === "high"
                                ? "bg-orange-900/20 border-orange-500/30"
                                : vuln.severity === "medium"
                                ? "bg-yellow-900/20 border-yellow-500/30"
                                : "bg-green-900/20 border-green-500/30"
                            }`}
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center space-x-2 mb-2">
                                  <Badge
                                    className={`${getRiskBadgeColor(
                                      vuln.severity
                                    )} text-white`}
                                  >
                                    {vuln.cve}
                                  </Badge>
                                  <Badge
                                    variant="outline"
                                    className="bg-slate-700 text-white border-slate-600"
                                  >
                                    {vuln.service}:{vuln.port}
                                  </Badge>
                                  <span
                                    className={`text-sm font-mono ${getCVSSColor(
                                      vuln.cvss_score
                                    )}`}
                                  >
                                    CVSS {vuln.cvss_score}
                                  </span>
                                </div>
                                <h4 className="font-semibold text-white mb-1">
                                  {vuln.description}
                                </h4>
                                <p className="text-sm text-slate-400">
                                  대상: {vuln.ip} • 발행일:{" "}
                                  {vuln.published_date}
                                </p>
                              </div>
                              <Badge
                                className={`${getRiskBadgeColor(
                                  vuln.severity
                                )} text-white ml-4`}
                              >
                                {vuln.severity.toUpperCase()}
                              </Badge>
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
                    <CardDescription className="text-slate-400">
                      SSH 및 웹 브루트포스 공격 결과
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {attackResults.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">
                        공격 결과가 없습니다.
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {attackResults.map((result, index) => (
                          <div
                            key={index}
                            className={`p-4 rounded-lg border ${
                              result.success
                                ? "bg-green-900/20 border-green-500/30"
                                : "bg-red-900/20 border-red-500/30"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-semibold text-white">
                                  {result.type.toUpperCase()} 공격 -{" "}
                                  {result.target}
                                </div>
                                <div className="text-sm text-slate-400">
                                  {result.message}
                                </div>
                                {result.credentials && (
                                  <div className="text-sm mt-2">
                                    <span className="text-green-400">
                                      발견된 인증정보:{" "}
                                      {result.credentials.username}/
                                      {result.credentials.password}
                                    </span>
                                  </div>
                                )}
                              </div>
                              <Badge
                                className={
                                  result.success ? "bg-green-600" : "bg-red-600"
                                }
                              >
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
                    <CardDescription className="text-slate-400">
                      스캔된 자산 및 서비스 정보
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {assets.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">
                        등록된 자산이 없습니다.
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {assets.map((asset, index) => (
                          <div
                            key={index}
                            className="p-4 bg-slate-800 rounded-lg border border-slate-700"
                          >
                            <div className="flex items-center justify-between mb-3">
                              <div>
                                <div className="flex items-center space-x-2">
                                  <span className="font-semibold text-white">
                                    {asset.ip}
                                  </span>
                                  {asset.risk_score && asset.risk_score > 0 && (
                                    <Badge
                                      className={`${
                                        asset.risk_score >= 50
                                          ? "bg-red-600"
                                          : asset.risk_score >= 20
                                          ? "bg-yellow-600"
                                          : "bg-green-600"
                                      } text-white`}
                                    >
                                      위험도: {asset.risk_score}
                                    </Badge>
                                  )}
                                </div>
                                <div className="text-sm text-slate-400">
                                  {asset.hostname} • {asset.os}
                                </div>
                                {(asset.critical_count ||
                                  asset.high_count ||
                                  asset.medium_count ||
                                  asset.low_count) && (
                                  <div className="flex space-x-2 mt-1">
                                    {asset.critical_count &&
                                      asset.critical_count > 0 && (
                                        <Badge className="bg-red-600 text-white text-xs">
                                          Critical: {asset.critical_count}
                                        </Badge>
                                      )}
                                    {asset.high_count &&
                                      asset.high_count > 0 && (
                                        <Badge className="bg-orange-600 text-white text-xs">
                                          High: {asset.high_count}
                                        </Badge>
                                      )}
                                    {asset.medium_count &&
                                      asset.medium_count > 0 && (
                                        <Badge className="bg-yellow-600 text-white text-xs">
                                          Medium: {asset.medium_count}
                                        </Badge>
                                      )}
                                    {asset.low_count && asset.low_count > 0 && (
                                      <Badge className="bg-green-600 text-white text-xs">
                                        Low: {asset.low_count}
                                      </Badge>
                                    )}
                                  </div>
                                )}
                              </div>
                              <div className="flex items-center space-x-2">
                                <Badge
                                  className={
                                    asset.status === "up"
                                      ? "bg-green-600"
                                      : "bg-red-600"
                                  }
                                >
                                  {asset.status}
                                </Badge>
                                <Button
                                  variant="destructive"
                                  size="sm"
                                  onClick={() =>
                                    handleDeleteAsset(asset.id, asset.ip)
                                  }
                                  className="h-8 w-8 p-0"
                                  title={`자산 ${asset.ip} 삭제`}
                                >
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              </div>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                              {asset.ports.map((port, portIndex) => (
                                <div
                                  key={portIndex}
                                  className="text-sm p-2 bg-slate-700 rounded"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-medium text-white">
                                      {port.port}
                                    </span>
                                    {port.risk_level && (
                                      <div
                                        className={`w-2 h-2 rounded-full ${getVulnerabilityColor(
                                          "open",
                                          port.risk_level
                                        )}`}
                                      />
                                    )}
                                  </div>
                                  <div className="text-xs text-slate-400">
                                    {port.service}
                                  </div>
                                  {port.version && (
                                    <div className="text-xs text-slate-400">
                                      {port.version}
                                    </div>
                                  )}
                                  {port.cve && port.cve.length > 0 && (
                                    <div className="text-xs text-red-400 mt-1">
                                      CVE: {port.cve.join(", ")}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                            <div className="text-xs text-slate-500 mt-2">
                              마지막 스캔:{" "}
                              {new Date(asset.last_scanned).toLocaleString()}
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
                      value={`[${new Date().toLocaleString()}] 대상에서 포트 스캔 시작: ${
                        targetIp || "미설정"
                      }
[${new Date().toLocaleString()}] 스캔 유형: ${scanType}
[${new Date().toLocaleString()}] 포트 범위: ${startPort}-${endPort}
[${new Date().toLocaleString()}] 타이밍 프로필: ${timingProfile}
${scanResults
  .map(
    (result) =>
      `[${new Date(result.timestamp).toLocaleString()}] 포트 ${result.port}/${
        result.service
      } ${result.status} ${result.version || ""} ${
        result.cve ? `CVE: ${result.cve.join(",")}` : ""
      }`
  )
  .join("\n")}
${attackResults
  .map(
    (result) =>
      `[${new Date(
        result.timestamp
      ).toLocaleString()}] ${result.type.toUpperCase()} 공격 ${
        result.target
      }: ${result.success ? "성공" : "실패"} - ${result.message}`
  )
  .join("\n")}
${vulnerabilities
  .map(
    (vuln) =>
      `[${new Date().toLocaleString()}] 취약점 발견: ${vuln.cve} (${
        vuln.severity
      }) - ${vuln.ip}:${vuln.port} ${vuln.service}`
  )
  .join("\n")}
[${new Date().toLocaleString()}] 스캔 완료. ${scanResults.length}개 포트, ${
                        vulnerabilities.length
                      }개 취약점 발견`}
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
  );
}
