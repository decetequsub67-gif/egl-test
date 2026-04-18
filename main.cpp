#include <jni.h>
#include <pthread.h>
#include <EGL/egl.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include "imgui-master/imgui.h"
#include "imgui-master/backends/imgui_impl_opengl3.h"
#include "And64InlineHook.hpp"
#include "font.h"

struct Vector2 { float x, y; };

struct UnityEngine_Touch_Fields { int32_t m_FingerId; Vector2 m_Position, m_RawPosition, m_PositionDelta; float m_TimeDelta; int32_t m_TapCount, m_Phase, m_Type; float m_Pressure, m_maximumPossiblePressure, m_Radius, m_RadiusVariance, m_AltitudeAngle, m_AzimuthAngle; };

enum TouchPhase { Began = 0, Moved = 1, Stationary = 2, Ended = 3, Canceled = 4 };

static int (*old_input_get_touchCount)();
static uintptr_t unity_base = 0;
static EGLBoolean (*oldEglSwapBuffers)(EGLDisplay, EGLSurface) = nullptr;
static bool testx = false;

uintptr_t get_base(const char* name) {
    uintptr_t addr = 0;
    char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, name) && strstr(line, "r-xp")) {
                sscanf(line, "%lx", &addr);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

static int input_get_touchCount() {
    static void *GetTouchPtr = (void*)(unity_base + 0x1D1B2D4);
    ImGuiIO &io = ImGui::GetIO();
    if (GetTouchPtr && old_input_get_touchCount) {
        int touchCount = old_input_get_touchCount();
        if (touchCount > 0) {
            UnityEngine_Touch_Fields touch = ((UnityEngine_Touch_Fields (*)(int))GetTouchPtr)(0);
            float reverseY = io.DisplaySize.y - touch.m_Position.y;
            switch (touch.m_Phase) {
                case Began: case Stationary: io.MousePos = ImVec2(touch.m_Position.x, reverseY); io.MouseDown[0] = true; break;
                case Ended: case Canceled: io.MouseDown[0] = false; break;
                case Moved: io.MousePos = ImVec2(touch.m_Position.x, reverseY); break;
            }
        }
    }
    return io.WantCaptureMouse ? 0 : (old_input_get_touchCount ? old_input_get_touchCount() : 0);
}

static EGLBoolean hookEglSwapBuffers(EGLDisplay d, EGLSurface s) {
    static bool init = false; EGLint w, h;
    eglQuerySurface(d, s, EGL_WIDTH, &w); eglQuerySurface(d, s, EGL_HEIGHT, &h);
    if (!init && w > 0 && h > 0) {
        ImGui::CreateContext(); 
		ImGui::GetIO().Fonts->AddFontFromMemoryTTF((void*)Roboto_Regular, sizeof(Roboto_Regular), 40.0f);
        ImGui_ImplOpenGL3_Init("#version 300 es");
        unity_base = get_base("libil2cpp.so");
        if (unity_base) 
            A64HookFunction((void*)(unity_base + 0x1D1B7A8), (void*)input_get_touchCount, (void**)&old_input_get_touchCount);
        init = true;
    }
    if (init) {
        ImGui::GetIO().DisplaySize = ImVec2((float)w, (float)h);
        ImGui_ImplOpenGL3_NewFrame(); 
		ImGui::NewFrame();
        ImGui::SetNextWindowSize(ImVec2(600, 600), ImGuiCond_Always);
        ImGui::Begin("plt egl"); 
		ImGui::Checkbox("Test", &testx); ImGui::End();
        ImGui::Render(); ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }
    return oldEglSwapBuffers(d, s);
}
//0x845944
static void gotplt() {
    uintptr_t libunity_base = 0;
    while (!libunity_base) {
        libunity_base = get_base("libunity.so");
    }
    //pasted without compilation error
    uintptr_t got = libunity_base + 0xF7F038;
    oldEglSwapBuffers = *(decltype(oldEglSwapBuffers)*)got;
    mprotect((void*)(got & ~0xFFF), 0x1000, PROT_READ | PROT_WRITE);
    *(uintptr_t*)got = (uintptr_t)hookEglSwapBuffers;
    mprotect((void*)(got & ~0xFFF), 0x1000, PROT_READ);
}

static void* cheat(void*) {
    gotplt();
    return nullptr;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    pthread_t t; pthread_create(&t, nullptr, cheat, nullptr);
    return JNI_VERSION_1_6;
}
