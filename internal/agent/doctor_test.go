package agent

import "testing"

func TestServiceCheckPlatform(t *testing.T) {
	check := serviceCheck("darwin", nil, nil, "/data")
	if check.Result != CheckOK || check.Detail != "systemd 서비스를 사용하지 않는 플랫폼입니다. deplite-agent start로 실행해주세요" {
		t.Fatalf("non-Linux service check = %+v", check)
	}
	check = serviceCheck("linux", nil, nil, "/data")
	if check.Result != CheckWarn || check.Detail != "systemd 서비스가 설정되어 있지 않습니다" {
		t.Fatalf("Linux service check without a unit = %+v", check)
	}
}
