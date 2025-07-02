#ifdef _WIN32
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#ifdef _WIN32
#include <crow.h>
#include <crow/middlewares/cors.h>
#else
#include "crow_all.h"
#include "crow/middlewares/cors.h"
#endif

#include <yaml-cpp/yaml.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <pugixml.hpp>
#include <sqlite3.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <sstream>
#include <map>
#include <iterator>
#include <mutex>
#include <cstdio>
#include <ctime>

using namespace std::chrono_literals;

// --- 데이터 모델 ---
struct Port {
    int id = -1;
    int port_number;
    std::string protocol;
    std::string state;
    std::string service_name;
    std::string product;
    std::string version;
    std::string extra_info;
    std::map<std::string, std::string> scripts;
};

struct Asset {
    int id = -1;
    std::string ip;
    std::string hostname;
    std::string os;
    std::string status;
    std::string last_scanned;
    std::vector<Port> ports;
};

// --- 글로벌 변수 ---
std::atomic<bool> g_running(true);

void signalHandler(int signum) {
    spdlog::warn("Signal {} received, shutting down...", signum);
    g_running = false;
}

// --- 설정 관리자 ---
class Config {
private:
    YAML::Node config;
public:
    Config(const std::string& filepath) {
        try { config = YAML::LoadFile(filepath); }
        catch (const YAML::Exception& e) {
            spdlog::error("Failed to load config file {}: {}", filepath, e.what());
            throw;
        }
    }
    std::string getString(const std::string& key, const std::string& defaultValue) const {
        try { return config[key].as<std::string>(); }
        catch (...) { return defaultValue; }
    }
    std::vector<std::string> getStringList(const std::string& key) const {
        std::vector<std::string> result;
        if (config[key]) {
            for (const auto& item : config[key]) result.push_back(item.as<std::string>());
        }
        return result;
    }
};

// --- 자산 저장소 ---
class AssetRepository {
private:
    sqlite3* db;
    std::string db_path;
    std::mutex db_mutex;

    void executeSQL(const std::string& sql) {
        char* errMsg = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            spdlog::error("SQL error: {}", errMsg);
            sqlite3_free(errMsg);
        }
    }

public:
    AssetRepository(const std::string& path) : db_path(path) {
        if (sqlite3_open(db_path.c_str(), &db)) {
            spdlog::error("Can't open database: {}", sqlite3_errmsg(db));
            throw std::runtime_error("Failed to open database");
        }
        spdlog::info("Database opened at {}", db_path);

        executeSQL(
            "CREATE TABLE IF NOT EXISTS assets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, hostname TEXT,"
            "os TEXT, status TEXT, last_scanned TEXT);"
        );
        executeSQL(
            "CREATE TABLE IF NOT EXISTS ports ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, port_number INTEGER NOT NULL,"
            "protocol TEXT, state TEXT, service_name TEXT, product TEXT, version TEXT, extra_info TEXT,"
            "FOREIGN KEY(asset_id) REFERENCES assets(id));"
        );
        executeSQL(
            "CREATE TABLE IF NOT EXISTS scripts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, port_id INTEGER, script_id TEXT, script_output TEXT,"
            "FOREIGN KEY(port_id) REFERENCES ports(id));"
        );
    }

    ~AssetRepository() {
        if (db) sqlite3_close(db);
    }

    void saveAsset(const Asset& asset) {
        std::lock_guard<std::mutex> lock(db_mutex);

        sqlite3_stmt* stmt;
        std::string sql = "INSERT INTO assets (ip, hostname, os, status, last_scanned) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, os=excluded.os, status=excluded.status, last_scanned=excluded.last_scanned;";

        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, asset.ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, asset.hostname.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, asset.os.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, asset.status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, asset.last_scanned.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            spdlog::error("Failed to save asset {}: {}", asset.ip, sqlite3_errmsg(db));
        }
        sqlite3_finalize(stmt);

        long long asset_id = sqlite3_last_insert_rowid(db);
        if (asset_id == 0) {
            sql = "SELECT id FROM assets WHERE ip = ?;";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, asset.ip.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                asset_id = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        if (asset_id == 0) {
            spdlog::error("Could not retrieve asset ID for IP {}", asset.ip);
            return;
        }
        sql = "DELETE FROM scripts WHERE port_id IN (SELECT id FROM ports WHERE asset_id = ?);";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_int(stmt, 1, asset_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        sql = "DELETE FROM ports WHERE asset_id = ?;";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        sqlite3_bind_int(stmt, 1, asset_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        for (const auto& port : asset.ports) {
            sql = "INSERT INTO ports (asset_id, port_number, protocol, state, service_name, product, version, extra_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_int(stmt, 1, asset_id);
            sqlite3_bind_int(stmt, 2, port.port_number);
            sqlite3_bind_text(stmt, 3, port.protocol.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, port.state.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, port.service_name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, port.product.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, port.version.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 8, port.extra_info.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                spdlog::error("Failed to save port {} for asset {}: {}", port.port_number, asset.ip, sqlite3_errmsg(db));
            }
            sqlite3_finalize(stmt);

            long long port_id = sqlite3_last_insert_rowid(db);
            if (port_id > 0) {
                for (const auto& [script_id, script_output] : port.scripts) {
                    sql = "INSERT INTO scripts (port_id, script_id, script_output) VALUES (?, ?, ?);";
                    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
                    sqlite3_bind_int(stmt, 1, port_id);
                    sqlite3_bind_text(stmt, 2, script_id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 3, script_output.c_str(), -1, SQLITE_STATIC);

                    if (sqlite3_step(stmt) != SQLITE_DONE) {
                        spdlog::error("Failed to save script result for port {}: {}", port.port_number, sqlite3_errmsg(db));
                    }
                    sqlite3_finalize(stmt);
                }
            }
        }
        spdlog::info("Asset {} and its {} ports saved.", asset.ip, asset.ports.size());
    }

    std::vector<Asset> getAllAssets() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<Asset> assets;
        sqlite3_stmt* stmt;
        std::string sql = "SELECT id, ip, hostname, os, status, last_scanned FROM assets;";

        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Asset asset;
            asset.id = sqlite3_column_int(stmt, 0);
            asset.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            asset.hostname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            asset.os = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            asset.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            asset.last_scanned = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            assets.push_back(asset);
        }
        sqlite3_finalize(stmt);

        for (auto& asset : assets) {
            sql = "SELECT id, port_number, protocol, state, service_name, product, version, extra_info FROM ports WHERE asset_id = ?;";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_int(stmt, 1, asset.id);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Port port;
                port.id = sqlite3_column_int(stmt, 0);
                port.port_number = sqlite3_column_int(stmt, 1);
                port.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                port.state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                port.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                port.product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                port.version = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
                port.extra_info = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
                asset.ports.push_back(port);
            }
            sqlite3_finalize(stmt);

            for (auto& port : asset.ports) {
                sqlite3_stmt* script_stmt;
                std::string script_sql = "SELECT script_id, script_output FROM scripts WHERE port_id = ?;";
                sqlite3_prepare_v2(db, script_sql.c_str(), -1, &script_stmt, 0);
                sqlite3_bind_int(script_stmt, 1, port.id);

                while (sqlite3_step(script_stmt) == SQLITE_ROW) {
                    std::string script_id = reinterpret_cast<const char*>(sqlite3_column_text(script_stmt, 0));
                    std::string script_output = reinterpret_cast<const char*>(sqlite3_column_text(script_stmt, 1));
                    port.scripts[script_id] = script_output;
                }
                sqlite3_finalize(script_stmt);
            }
        }
        return assets;
    }
};

// --- 스캔 오케스트레이터 ---
class ScanOrchestrator {
private:
    std::shared_ptr<Config> config;
    std::shared_ptr<AssetRepository> assetRepo;

    std::pair<std::string, int> executeCommand(const std::string& command) {
        std::string result;
#ifdef _WIN32
        FILE* pipe = _popen(command.c_str(), "r");
#else
        FILE* pipe = popen(command.c_str(), "r");
#endif
        if (!pipe) return std::make_pair("", -1);
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
#ifdef _WIN32
        int exit_code = _pclose(pipe);
#else
        int exit_code = pclose(pipe);
#endif
        return std::make_pair(result, exit_code);
    }

    Asset parseNmapXml(const std::string& xml_output) {
        pugi::xml_document doc;
        Asset asset;
        if (!doc.load_string(xml_output.c_str())) {
            spdlog::error("Failed to parse nmap XML output.");
            return asset;
        }
        pugi::xml_node host_node = doc.child("nmaprun").child("host");
        if (!host_node) {
            spdlog::warn("No host found in nmap output. Target may be down.");
            return asset;
        }
        asset.status = host_node.child("status").attribute("state").as_string();
        asset.ip = host_node.child("address").attribute("addr").as_string();
        if (asset.status != "up") {
            spdlog::info("Target {} is not up. Status: {}", asset.ip, asset.status);
            return asset;
        }
        pugi::xml_node hostnames_node = host_node.child("hostnames");
        if (hostnames_node) {
            pugi::xml_node hostname_node = hostnames_node.child("hostname");
            if (hostname_node) {
                asset.hostname = hostname_node.attribute("name").as_string();
            }
        }
        pugi::xml_node os_node = host_node.child("os");
        if (os_node) {
            pugi::xml_node os_match = os_node.child("osmatch");
            if (os_match) {
                asset.os = os_match.attribute("name").as_string();
            }
        }
        pugi::xml_node ports_node = host_node.child("ports");
        if (ports_node) {
            for (pugi::xml_node port_node : ports_node.children("port")) {
                Port port;
                port.port_number = port_node.attribute("portid").as_int();
                port.protocol = port_node.attribute("protocol").as_string();
                port.state = port_node.child("state").attribute("state").as_string();
                if (port.state == "open") {
                    pugi::xml_node service_node = port_node.child("service");
                    if (service_node) {
                        port.service_name = service_node.attribute("name").as_string();
                        port.product = service_node.attribute("product").as_string();
                        port.version = service_node.attribute("version").as_string();
                        port.extra_info = service_node.attribute("extrainfo").as_string();
                    }
                    for (pugi::xml_node script_node : port_node.children("script")) {
                        std::string script_id = script_node.attribute("id").as_string();
                        std::string script_output = script_node.attribute("output").as_string();
                        port.scripts[script_id] = script_output;
                    }
                }
                asset.ports.push_back(port);
            }
        }
        return asset;
    }

public:
    ScanOrchestrator(std::shared_ptr<Config> cfg, std::shared_ptr<AssetRepository> repo)
        : config(cfg), assetRepo(repo) {}

    void scanTarget(const std::string& target) {
        spdlog::info("Starting scan for target: {}", target);
        std::string nmap_path = config->getString("scanner.nmap.path", "nmap");
        std::string nmap_args = config->getString("scanner.nmap.arguments", "-sV -O --script=default");
        std::string command = nmap_path + " " + nmap_args + " -oX - " + target;
        spdlog::debug("Executing command: {}", command);
        try {
            auto [xml_output, exit_code] = executeCommand(command);
            if (exit_code != 0) {
                spdlog::error("Nmap scan for {} failed with exit code {}", target, exit_code);
                return;
            }
            Asset asset = parseNmapXml(xml_output);
            auto now = std::chrono::system_clock::now();
            std::time_t now_time = std::chrono::system_clock::to_time_t(now);
            char time_buf[20];
            std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time));
            asset.last_scanned = time_buf;
            if (!asset.ip.empty()) {
                assetRepo->saveAsset(asset);
                spdlog::info("Scan for {} completed successfully.", target);
            } else {
                spdlog::warn("Scan for {} did not return a valid asset.", target);
            }
        }
        catch (const std::exception& e) {
            spdlog::error("Failed to execute nmap process for target {}: {}", target, e.what());
            return;
        }
    }
};

// --- Crow HTTP 서버 ---
class HTTPServer {
private:
    crow::App<crow::CORSHandler> app;
    std::shared_ptr<AssetRepository> assetRepo;
    std::shared_ptr<ScanOrchestrator> orchestrator;
    int port;

public:
    HTTPServer(int p, std::shared_ptr<AssetRepository> repo, std::shared_ptr<ScanOrchestrator> orch)
        : assetRepo(repo), orchestrator(orch), port(p) {

        auto& cors = app.get_middleware<crow::CORSHandler>();
        cors.global()
            .origin("*")
            .methods("GET"_method, "POST"_method, "OPTIONS"_method)
            .headers("Content-Type");

        // OPTIONS 핸들러 직접 추가 (CORS 해결용)
        CROW_ROUTE(app, "/api/assets").methods("OPTIONS"_method)
        ([](const crow::request& req){
            crow::response res;
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.code = 204;
            return res;
        });

        CROW_ROUTE(app, "/api/scan").methods("OPTIONS"_method)
        ([](const crow::request& req){
            crow::response res;
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.code = 204;
            return res;
        });

        CROW_ROUTE(app, "/api/assets")
        ([this]() {
            auto assets = this->assetRepo->getAllAssets();
            crow::json::wvalue response;
            for (size_t i = 0; i < assets.size(); ++i) {
                crow::json::wvalue asset_json;
                asset_json["id"] = assets[i].id;
                asset_json["ip"] = assets[i].ip;
                asset_json["hostname"] = assets[i].hostname;
                asset_json["os"] = assets[i].os;
                asset_json["status"] = assets[i].status;
                asset_json["last_scanned"] = assets[i].last_scanned;
                for (size_t j = 0; j < assets[i].ports.size(); ++j) {
                    asset_json["ports"][j]["port"] = assets[i].ports[j].port_number;
                    asset_json["ports"][j]["protocol"] = assets[i].ports[j].protocol;
                    asset_json["ports"][j]["state"] = assets[i].ports[j].state;
                    asset_json["ports"][j]["service"] = assets[i].ports[j].service_name;
                    asset_json["ports"][j]["product"] = assets[i].ports[j].product;
                    asset_json["ports"][j]["version"] = assets[i].ports[j].version;
                    if (!assets[i].ports[j].scripts.empty()) {
                        for (const auto& [id, output] : assets[i].ports[j].scripts) {
                            asset_json["ports"][j]["scripts"][id] = output;
                        }
                    }
                }
                response[i] = std::move(asset_json);
            }
            return response;
        });

        CROW_ROUTE(app, "/api/scan").methods("POST"_method)
        ([this](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body || !body.has("target")) {
                return crow::response(400, "JSON body with 'target' key is required.");
            }
            std::string target = body["target"].s();
            std::thread([this, target]() { this->orchestrator->scanTarget(target); }).detach();
            return crow::response(202, "Scan request accepted for target: " + target);
        });
    }

    void start() {
        spdlog::info("Starting HTTP server on port {}", port);
        app.port(port).multithreaded().run_async();
    }
    void stop() { app.stop(); }
};

// --- ASMApplication 클래스 및 main 함수 ---
class ASMApplication {
private:
    std::shared_ptr<Config> config;
    std::shared_ptr<AssetRepository> assetRepo;
    std::shared_ptr<ScanOrchestrator> orchestrator;
    std::shared_ptr<HTTPServer> httpServer;

    void setupLogging() {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("asm.log", 1024 * 1024 * 5, 3);
        file_sink->set_level(spdlog::level::debug);
        std::vector<spdlog::sink_ptr> sinks{ console_sink, file_sink };
        auto logger = std::make_shared<spdlog::logger>("asm", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::debug);
        spdlog::register_logger(logger);
        spdlog::set_default_logger(logger);
    }

    void shutdown() {
        spdlog::info("Shutting down ASM system...");
        httpServer->stop();
        spdlog::info("Shutdown complete.");
    }

public:
    ASMApplication(const std::string& configPath) {
        setupLogging();
        try {
            config = std::make_shared<Config>(configPath);
            assetRepo = std::make_shared<AssetRepository>(config->getString("database.path", "asm.db"));
            orchestrator = std::make_shared<ScanOrchestrator>(config, assetRepo);
            int apiPort = std::stoi(config->getString("api.port", "8080"));
            httpServer = std::make_shared<HTTPServer>(apiPort, assetRepo, orchestrator);
        }
        catch (const std::exception& e) {
            spdlog::critical("Initialization failed: {}", e.what());
            exit(1);
        }
    }

    void run() {
        spdlog::info("ASM System starting...");
        httpServer->start();
        auto initial_targets = config->getStringList("targets.initial");
        if (!initial_targets.empty()) {
            spdlog::info("Running initial scans on {} target(s)...", initial_targets.size());
            for (const auto& target : initial_targets) {
                orchestrator->scanTarget(target);
            }
            spdlog::info("Initial scans complete.");
        }
        while (g_running) {
            std::this_thread::sleep_for(1s);
        }
        shutdown();
    }
};

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    std::string configPath = "config.yaml";
    if (argc > 1) configPath = argv[1];
    std::ifstream f(configPath.c_str());
    if (!f.good()) {
        std::cout << "Configuration file '" << configPath << "' not found. Creating a default config.\n";
        std::ofstream configFile(configPath);
        configFile << "api:\n"
                   << "  port: 8080\n\n"
                   << "database:\n"
                   << "  path: asm.db\n\n"
                   << "scanner:\n"
                   << "  nmap:\n"
                   << "    path: nmap\n"
                   << "    arguments: \"-sV -O --script=vuln\"\n\n"
                   << "targets:\n"
                   << "  initial: []\n";
        configFile.close();
        std::cout << "Default 'config.yaml' created. Please set your targets and restart.\n";
        return 0;
    }
    try {
        ASMApplication app(configPath);
        app.run();
    }
    catch (const std::exception& e) {
        spdlog::critical("An unhandled exception occurred: {}", e.what());
        return 1;
    }
    return 0;
}
