#include <Windows.h>
#include <cstdio>
#include <cstring>

struct CVector { float x, y, z; };

// PE timestamp fingerprints per version
// 1.0 EN = 0x504D6947, JP = 0x40758BC6
enum GameVersion { VER_10EN, VER_JP, VER_UNKNOWN };
static GameVersion g_version = VER_UNKNOWN;

static GameVersion DetectVersion() {
    BYTE* base = (BYTE*)0x400000;
    DWORD pe = *(DWORD*)(base + 0x3C);
    DWORD ts = *(DWORD*)(base + pe + 8);
    if (ts == 0x504D6947) return VER_10EN;
    if (ts == 0x40758BC6) return VER_JP;
    return VER_UNKNOWN;
}

// -------------------------------------------------------
// addresses per version
// -------------------------------------------------------

struct AddrTable {
    DWORD FindPlayerPed;
    DWORD FindPlayerVehicle;
    DWORD FindPlayerEntity;
    DWORD SetHelpMessage;
    DWORD ApplyMoveSpeed;
    DWORD SetObjective;
    DWORD WarpPedIntoCar;
    DWORD CameraSetBehindPlayer;
    DWORD RestoreWithJumpCut;
    DWORD GetEngineStatus;
    DWORD SetEngineStatus;
    DWORD TheCamera;
    DWORD GameTimer;
    DWORD ProcessScripts;
    DWORD HookSiteProcessScripts;
    DWORD HookSiteRestartGame;
};

static const AddrTable kAddr_10EN = {
    0x4BC120, // FindPlayerPed
    0x4BC1E0, // FindPlayerVehicle
    0x4BC1B0, // FindPlayerEntity
    0x55BFC0, // SetHelpMessage
    0x4BAC70, // ApplyMoveSpeed
    0x521F10, // SetObjective
    0x4EF8B0, // WarpPedIntoCar
    0x46BADE, // CameraSetBehindPlayer
    0x46BB24, // RestoreWithJumpCut
    0x5A97E0, // GetEngineStatus
    0x5A97F0, // SetEngineStatus
    0x7E4688, // TheCamera
    0x974B2C, // GameTimer
    0x5A92E0, // ProcessScripts
    0x4A45AA, // HookSiteProcessScripts
    0x4A46F1, // HookSiteRestartGame
};

static const AddrTable kAddr_JP = {
    0x4BBA40,
    0x4BBB00,
    0x4BBAD0,
    0x55C180,
    0x4BA590,
    0x5218B0,
    0x4EF220,
    0x46BE4E,
    0x46BE94,
    0x5A95A0,
    0x5A95B0,
    0x7E1690,
    0x971B34,
    0x5A90A0,
    0x4A3ECA,
    0x4A4011,
};

static const AddrTable* g_addr = nullptr;

typedef void* (__cdecl* FindPlayerPed_t)();
typedef void* (__cdecl* FindPlayerVehicle_t)();
typedef void* (__cdecl* FindPlayerEntity_t)();
typedef void(__cdecl* SetHelpMessage_t)(const wchar_t*, bool, bool);
typedef void(__thiscall* ApplyMoveSpeed_t)(void*);
typedef void(__thiscall* CameraSetBehindPlayer_t)(void*);
typedef void(__thiscall* SetObjective_t)(void*, int, void*);
typedef void(__thiscall* WarpPedIntoCar_t)(void*, void*);
typedef void(__thiscall* RestoreWithJumpCut_t)(void*);
typedef unsigned int(__thiscall* GetEngineStatus_t)(void*);
typedef void(__thiscall* SetEngineStatus_t)(void*, unsigned int);
typedef void(__cdecl* ProcessScripts_t)();
typedef void(__cdecl* RestartGameFn_t)();

static FindPlayerPed_t         FindPlayerPed;
static FindPlayerVehicle_t     FindPlayerVehicle;
static FindPlayerEntity_t      FindPlayerEntity;
static SetHelpMessage_t        SetHelpMessage;
static ApplyMoveSpeed_t        ApplyMoveSpeed;
static CameraSetBehindPlayer_t CameraSetBehindPlayer;
static SetObjective_t          SetObjective;
static WarpPedIntoCar_t        WarpPedIntoCar;
static GetEngineStatus_t       GetEngineStatusFn;
static SetEngineStatus_t       SetEngineStatusFn;
static RestoreWithJumpCut_t    RestoreWithJumpCut;
static ProcessScripts_t        ProcessScripts_Original;
static RestartGameFn_t         RestartGame_Original;

static void* TheCamera;
static int* GameTimer;

// -------------------------------------------------------
// engine field accessors
// -------------------------------------------------------

inline CVector GetPosition(void* e) { return *(CVector*)((BYTE*)e + 0x34); }
inline CVector GetMoveSpeed(void* e) { return *(CVector*)((BYTE*)e + 0x70); }
inline void SetMoveSpeed(void* e, CVector v) { *(CVector*)((BYTE*)e + 0x70) = v; }

// vtable[11] = CEntity::SetPosn
inline void Teleport(void* e, CVector pos) {
    auto vtbl = *(void***)e;
    ((void(__thiscall*)(void*, CVector))vtbl[11])(e, pos);
}

inline CVector GetMatrixRight(void* v) { return *(CVector*)((BYTE*)v + 0x04); }
inline CVector GetMatrixUp(void* v) { return *(CVector*)((BYTE*)v + 0x14); }
inline void SetMatrixRight(void* v, CVector r) { *(CVector*)((BYTE*)v + 0x04) = r; }
inline void SetMatrixUp(void* v, CVector u) { *(CVector*)((BYTE*)v + 0x14) = u; }

inline float GetPedHealth(void* ped) { return *(float*)((BYTE*)ped + 0x354); }
inline float GetVehicleHealth(void* veh) { return *(float*)((BYTE*)veh + 0x204); }
inline void  SetPedHealth(void* ped, float h) { *(float*)((BYTE*)ped + 0x354) = h; }
inline void  SetVehicleHealth(void* veh, float h) { *(float*)((BYTE*)veh + 0x204) = h; }

inline bool IsInVehicle(void* ped) { return *(BYTE*)((BYTE*)ped + 0x3AC) != 0; }

// DamageManager is embedded inside CAutomobile at +0x2A0
inline void* GetDamageManager(void* car) { return (BYTE*)car + 0x2A0; }
inline unsigned int GetEngineStatus(void* car) { return GetEngineStatusFn(GetDamageManager(car)); }
inline void SetEngineStatus(void* car, unsigned int s) { SetEngineStatusFn(GetDamageManager(car), s); }

// active camera at +0x188, vertical/horizontal angles at +0xAC and +0xBC
inline float GetCameraVertical() { return *(float*)((BYTE*)TheCamera + 0x188 + 0xAC); }
inline float GetCameraHorizontal() { return *(float*)((BYTE*)TheCamera + 0x188 + 0xBC); }
inline void  SetCameraVertical(float v) { *(float*)((BYTE*)TheCamera + 0x188 + 0xAC) = v; }
inline void  SetCameraHorizontal(float v) { *(float*)((BYTE*)TheCamera + 0x188 + 0xBC) = v; }

// -------------------------------------------------------
// saved state
// -------------------------------------------------------

static CVector      s_vposition = { 0,0,0 };
static CVector      s_pposition = { 0,0,0 };
static CVector      s_vspeed = { 0,0,0 };
static CVector      s_pspeed = { 0,0,0 };
static void* s_lastVehicle = nullptr;
static CVector      s_matRight = { 0,0,0 };
static CVector      s_matUp = { 0,0,0 };
static float        s_vhealth = 10000.0f;
static float        s_phealth = 100.0f;
static unsigned int s_engineStatus = 0;
static float        s_camH = 0.0f, s_camV = 0.0f;
static int          s_lastSpawnedTime = 0;
static bool         s_vpositionSet = false;
static bool         s_ppositionSet = false;
static wchar_t      s_msgBuf[1024];

static int g_keySave = VK_TAB;
static int g_keyLoadVeh = '1';
static int g_keyLoadFoot = '2';

void ResetState() {
    s_vposition = s_pposition = s_vspeed = s_pspeed = { 0,0,0 };
    s_matRight = s_matUp = { 0,0,0 };
    s_lastVehicle = nullptr;
    s_vhealth = 10000.0f;
    s_phealth = 100.0f;
    s_engineStatus = 0;
    s_camH = s_camV = 0.0f;
    s_lastSpawnedTime = 0;
    s_vpositionSet = s_ppositionSet = false;
}

// -------------------------------------------------------

void OnProcessScripts() {
    void* ped = FindPlayerPed();
    void* vehicle = FindPlayerVehicle();
    void* entity = FindPlayerEntity();
    if (!ped || !entity) return;

    bool inVehicle = IsInVehicle(ped);
    int  timer = *GameTimer;

    // key 1: load vehicle checkpoint, or warp back into the car if on foot
    if (GetAsyncKeyState(g_keyLoadVeh) & 0x8000) {
        if (timer > s_lastSpawnedTime + 1000) {
            if (inVehicle && vehicle) {
                // first press with no checkpoint yet: capture current state
                if (!s_vpositionSet) {
                    s_lastVehicle = vehicle;
                    s_vposition = GetPosition(entity);
                    s_vspeed = GetMoveSpeed(vehicle);
                    s_matRight = GetMatrixRight(vehicle);
                    s_matUp = GetMatrixUp(vehicle);
                    s_engineStatus = GetEngineStatus(vehicle);
                    s_vpositionSet = true;
                }

                SetPedHealth(ped, s_phealth);
                SetVehicleHealth(vehicle, s_vhealth);
                SetEngineStatus(vehicle, s_engineStatus);
                Teleport(entity, s_vposition);
                SetMoveSpeed(vehicle, s_vspeed);
                SetMatrixRight(vehicle, s_matRight);
                SetMatrixUp(vehicle, s_matUp);
                CameraSetBehindPlayer(TheCamera);

                s_lastSpawnedTime = timer;
                wcscpy_s(s_msgBuf, L"Loaded");
                SetHelpMessage(s_msgBuf, true, false);
            }
            else if (!inVehicle && s_lastVehicle && s_vpositionSet) {
                SetObjective(ped, 0x12, s_lastVehicle);
                WarpPedIntoCar(ped, s_lastVehicle);

                SetPedHealth(ped, s_phealth);
                SetVehicleHealth(s_lastVehicle, s_vhealth);
                SetEngineStatus(s_lastVehicle, s_engineStatus);
                Teleport(s_lastVehicle, s_vposition);
                SetMoveSpeed(s_lastVehicle, s_vspeed);
                SetMatrixRight(s_lastVehicle, s_matRight);
                SetMatrixUp(s_lastVehicle, s_matUp);
                RestoreWithJumpCut(TheCamera);
                CameraSetBehindPlayer(TheCamera);

                s_lastSpawnedTime = timer;
                wcscpy_s(s_msgBuf, L"Loaded");
                SetHelpMessage(s_msgBuf, true, false);
            }
        }
    }

    // key 2: load on-foot checkpoint (only works while on foot)
    if (GetAsyncKeyState(g_keyLoadFoot) & 0x8000) {
        if (timer > s_lastSpawnedTime + 1000) {
            if (!inVehicle) {
                if (!s_ppositionSet) {
                    s_pposition = GetPosition(entity);
                    s_pspeed = GetMoveSpeed(ped);
                    s_ppositionSet = true;
                }

                SetPedHealth(ped, s_phealth);
                if (vehicle) SetVehicleHealth(vehicle, s_vhealth);
                Teleport(entity, s_pposition);
                SetMoveSpeed(ped, s_pspeed);
                ApplyMoveSpeed(ped);
                SetCameraVertical(s_camV);
                SetCameraHorizontal(s_camH);

                s_lastSpawnedTime = timer;
                wcscpy_s(s_msgBuf, L"Loaded");
                SetHelpMessage(s_msgBuf, true, false);
            }
        }
    }

    // Tab: save current state
    if (GetAsyncKeyState(g_keySave) & 0x8000) {
        if (timer > s_lastSpawnedTime + 1000) {
            if (vehicle) s_vhealth = GetVehicleHealth(vehicle);
            s_phealth = GetPedHealth(ped);

            if (!inVehicle) {
                s_pposition = GetPosition(entity);
                s_pspeed = GetMoveSpeed(ped);
                s_camV = GetCameraVertical();
                s_camH = GetCameraHorizontal();
                s_ppositionSet = true;
            }
            else if (vehicle) {
                s_lastVehicle = vehicle;
                s_engineStatus = GetEngineStatus(vehicle);
                s_vposition = GetPosition(entity);
                s_vspeed = GetMoveSpeed(vehicle);
                s_matRight = GetMatrixRight(vehicle);
                s_matUp = GetMatrixUp(vehicle);
                s_vpositionSet = true;
            }

            s_lastSpawnedTime = timer;
            wcscpy_s(s_msgBuf, L"Set");
            SetHelpMessage(s_msgBuf, true, false);
        }
    }
}

// -------------------------------------------------------
// hooks
// -------------------------------------------------------

static BYTE s_processScriptsOrigBytes[5];
static BYTE s_restartGameOrigBytes[5];

void __cdecl HookedProcessScripts() {
    ProcessScripts_Original();
    OnProcessScripts();
}

void __cdecl HookedRestartGame() {
    RestartGame_Original();
    ResetState();
}

void PatchCall(DWORD callSite, void* newFn, BYTE* savedBytes, RestartGameFn_t* outOriginal = nullptr) {
    DWORD oldProtect;
    VirtualProtect((void*)callSite, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    DWORD origRel = *(DWORD*)(callSite + 1);
    DWORD origAddr = (callSite + 5) + origRel;
    if (outOriginal)
        *outOriginal = (RestartGameFn_t)origAddr;

    memcpy(savedBytes, (void*)callSite, 5);

    DWORD newRel = (DWORD)newFn - (callSite + 5);
    BYTE  patch[5] = { 0xE8 };
    memcpy(patch + 1, &newRel, 4);
    memcpy((void*)callSite, patch, 5);

    VirtualProtect((void*)callSite, 5, oldProtect, &oldProtect);
}

void InitFunctionPointers() {
    const AddrTable& a = *g_addr;

    FindPlayerPed = (FindPlayerPed_t)a.FindPlayerPed;
    FindPlayerVehicle = (FindPlayerVehicle_t)a.FindPlayerVehicle;
    FindPlayerEntity = (FindPlayerEntity_t)a.FindPlayerEntity;
    SetHelpMessage = (SetHelpMessage_t)a.SetHelpMessage;
    ApplyMoveSpeed = (ApplyMoveSpeed_t)a.ApplyMoveSpeed;
    CameraSetBehindPlayer = (CameraSetBehindPlayer_t)a.CameraSetBehindPlayer;
    SetObjective = (SetObjective_t)a.SetObjective;
    WarpPedIntoCar = (WarpPedIntoCar_t)a.WarpPedIntoCar;
    GetEngineStatusFn = (GetEngineStatus_t)a.GetEngineStatus;
    SetEngineStatusFn = (SetEngineStatus_t)a.SetEngineStatus;
    RestoreWithJumpCut = (RestoreWithJumpCut_t)a.RestoreWithJumpCut;
    ProcessScripts_Original = (ProcessScripts_t)a.ProcessScripts;
    TheCamera = (void*)a.TheCamera;
    GameTimer = (int*)a.GameTimer;
}

void InstallHooks() {
    const AddrTable& a = *g_addr;
    PatchCall(a.HookSiteProcessScripts, (void*)HookedProcessScripts, s_processScriptsOrigBytes);
    PatchCall(a.HookSiteRestartGame, (void*)HookedRestartGame, s_restartGameOrigBytes, &RestartGame_Original);
}

static int ParseKey(const char* str) {
    if (_stricmp(str, "VK_TAB") == 0) return VK_TAB;
    if (_stricmp(str, "VK_SPACE") == 0) return VK_SPACE;
    if (_stricmp(str, "VK_RETURN") == 0) return VK_RETURN;
    if (_stricmp(str, "VK_SHIFT") == 0) return VK_SHIFT;
    if (_stricmp(str, "VK_CONTROL") == 0) return VK_CONTROL;
    if (_stricmp(str, "VK_MENU") == 0) return VK_MENU;
    if (_stricmp(str, "VK_INSERT") == 0) return VK_INSERT;
    if (_stricmp(str, "VK_DELETE") == 0) return VK_DELETE;
    if (_stricmp(str, "VK_HOME") == 0) return VK_HOME;
    if (_stricmp(str, "VK_END") == 0) return VK_END;
    if (_stricmp(str, "VK_PRIOR") == 0) return VK_PRIOR;
    if (_stricmp(str, "VK_NEXT") == 0) return VK_NEXT;
    for (int i = 1; i <= 12; i++) {
        char buf[8]; sprintf_s(buf, "VK_F%d", i);
        if (_stricmp(str, buf) == 0) return VK_F1 + i - 1;
    }
    if (str[0] && !str[1]) return toupper((unsigned char)str[0]);
    return -1;
}

static void LoadConfig() {
    char iniPath[MAX_PATH];
    GetModuleFileNameA(nullptr, iniPath, MAX_PATH);
    char* slash = strrchr(iniPath, '\\');
    if (slash) strcpy_s(slash + 1, MAX_PATH - (slash - iniPath) - 1, "checkpoint.ini");

    char buf[64];
    int k;

    GetPrivateProfileStringA("Keys", "Save", "VK_TAB", buf, sizeof(buf), iniPath);
    if ((k = ParseKey(buf)) != -1) g_keySave = k;

    GetPrivateProfileStringA("Keys", "LoadVehicle", "1", buf, sizeof(buf), iniPath);
    if ((k = ParseKey(buf)) != -1) g_keyLoadVeh = k;

    GetPrivateProfileStringA("Keys", "LoadOnFoot", "2", buf, sizeof(buf), iniPath);
    if ((k = ParseKey(buf)) != -1) g_keyLoadFoot = k;
}

// -------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        g_version = DetectVersion();
        switch (g_version) {
        case VER_10EN: g_addr = &kAddr_10EN; break;
        case VER_JP:   g_addr = &kAddr_JP;   break;
        default:
            MessageBoxA(nullptr,
                "VC_LinePracticeUtil: unsupported game version.\n"
                "Only GTA VC 1.0 EN and JP are supported.",
                "Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }

        InitFunctionPointers();
        LoadConfig();
        InstallHooks();
    }
    return TRUE;
}