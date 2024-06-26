import useSWR from "swr";
import { useRef } from "react";
import { useTranslation } from "react-i18next";
import { IconButton, Tooltip } from "@mui/material";
import { PrivacyTipRounded, Settings, InfoRounded } from "@mui/icons-material";
import {
  checkService,
  grantPermission,
  installService,
  restartSidecar,
} from "@/services/cmds";
import { useVerge } from "@/hooks/use-verge";
import { DialogRef, Notice, Switch } from "@/components/base";
import { SettingList, SettingItem } from "./mods/setting-comp";
import { GuardState } from "./mods/guard-state";
import { ServiceViewer } from "./mods/service-viewer";
import { SysproxyViewer } from "./mods/sysproxy-viewer";
import { TunViewer } from "./mods/tun-viewer";
import getSystem from "@/utils/get-system";
import { invoke } from "@tauri-apps/api/tauri";
import { TooltipIcon } from "@/components/base/base-tooltip-icon";
interface Props {
  onError?: (err: Error) => void;
}

const SettingSystem = ({ onError }: Props) => {
  const { t } = useTranslation();

  const { verge, mutateVerge, patchVerge } = useVerge();

  // service mode
  const { data: serviceStatus } = useSWR("checkService", checkService, {
    revalidateIfStale: false,
    shouldRetryOnError: false,
    focusThrottleInterval: 36e5, // 1 hour
  });

  const serviceRef = useRef<DialogRef>(null);
  const sysproxyRef = useRef<DialogRef>(null);
  const tunRef = useRef<DialogRef>(null);

  const {
    enable_tun_mode,
    enable_auto_launch,
    enable_service_mode,
    enable_silent_start,
    enable_system_proxy,
  } = verge ?? {};

  const onSwitchFormat = (_e: any, value: boolean) => value;
  const onChangeData = (patch: Partial<IVergeConfig>) => {
    mutateVerge({ ...verge, ...patch }, false);
  };
  const { clash_core = "verge-mihomo" } = verge ?? {};
  const OS = getSystem();
  const isWIN = getSystem() === "windows";
  const onGuard = async (e: boolean) => {
    if (OS === "macos" || OS === "linux") {
      try {
        await grantPermission(clash_core);
      } catch (err: any) {
        Notice.error(err?.message || err.toString());
        return false;
      }
      await restartSidecar();
    } else {
      try {
        const result = await invoke<any>("check_service");
        if (result?.code !== 0 && result?.code !== 400) {
          await installService();
        }
      } catch (err: any) {
        try {
          await installService();
        } catch (err: any) {
          Notice.error(err?.message || err.toString());
          return false;
        }
      }
    }
    return true;
  };
  return (
    <SettingList title={t("System Setting")}>
      <SysproxyViewer ref={sysproxyRef} />
      <TunViewer ref={tunRef} />
      <ServiceViewer ref={serviceRef} enable={!!enable_service_mode} />

      <SettingItem
        label={t("Tun Mode")}
        extra={
          <TooltipIcon
            title={t("Tun Mode Info")}
            icon={Settings}
            onClick={() => tunRef.current?.open()}
          />
        }
      >
        <GuardState
          value={enable_tun_mode ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={async (e) => {
            if (e === false || (await onGuard(e))) {
              const vergeOptions = isWIN
                ? { enable_service_mode: true, enable_tun_mode: e }
                : { enable_tun_mode: e };
              patchVerge(vergeOptions);
              onChangeData(vergeOptions);
            }
          }}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem
        label={t("Service Mode")}
        extra={
          <TooltipIcon
            title={t("Service Mode Info")}
            icon={PrivacyTipRounded}
            onClick={() => serviceRef.current?.open()}
          />
        }
      >
        <GuardState
          value={enable_service_mode ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_service_mode: e })}
          onGuard={(e) => patchVerge({ enable_service_mode: e })}
        >
          <Switch
            edge="end"
            disabled={
              serviceStatus !== "active" && serviceStatus !== "installed"
            }
          />
        </GuardState>
      </SettingItem>

      <SettingItem
        label={t("System Proxy")}
        extra={
          <>
            <TooltipIcon
              title={t("System Proxy Info")}
              icon={Settings}
              onClick={() => sysproxyRef.current?.open()}
            />
          </>
        }
      >
        <GuardState
          value={enable_system_proxy ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_system_proxy: e })}
          onGuard={(e) => patchVerge({ enable_system_proxy: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem label={t("Auto Launch")}>
        <GuardState
          value={enable_auto_launch ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_auto_launch: e })}
          onGuard={(e) => patchVerge({ enable_auto_launch: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem
        label={t("Silent Start")}
        extra={<TooltipIcon title={t("Silent Start Info")} />}
      >
        <GuardState
          value={enable_silent_start ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_silent_start: e })}
          onGuard={(e) => patchVerge({ enable_silent_start: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>
    </SettingList>
  );
};

export default SettingSystem;
