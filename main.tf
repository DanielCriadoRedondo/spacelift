# Spacelift VDP — sonda de aislamiento worker→host (SOLO LECTURA, PoC mínima)
#
# Objetivo del programa (ficha): "Container Escape from Worker to Host". El reverse
# shell en el worker es por diseño y NO es vuln; lo reportable es ESCAPAR al host /
# acceder a otros tenants / exfiltrar fuera del scope del job.
#
# ESTRICTAMENTE READ-ONLY: solo lee/stat/lista/GET. NO escribe, NO conecta a sockets,
# NO descarga cuerpos de credenciales (IMDS/SA token: solo presencia/nombre de rol).
# NO persiste, NO pivota. Es una EVALUACIÓN DE AISLAMIENTO, no un exploit. Si algún
# check revela acceso al host o a credenciales del host → PARAR y documentar PoC mínima.
#
# Uso: Spacelift ejecuta este Terraform en un run; el log del run (solo visible para la
# cuenta propia) contiene la salida. Interpretación: ver README.md de esta carpeta.

terraform {
  required_version = ">= 1.0"
}

resource "null_resource" "isolation_probe" {
  triggers = { always = timestamp() }

  provisioner "local-exec" {
    command = <<-EOT
      set +e
      echo "===== INTIGRITI VDP — container isolation probe (READ-ONLY) ====="

      echo "## 1. identidad / runtime"
      id; hostname; uname -a
      test -f /.dockerenv && echo "marker:/.dockerenv"; test -f /run/.containerenv && echo "marker:/run/.containerenv"
      echo "-- /proc/1/cgroup --"; cat /proc/1/cgroup 2>/dev/null | head
      echo "-- userns (uid_map; '0 0 4294967295' = sin remap) --"; cat /proc/self/uid_map 2>/dev/null
      echo "-- PID ns self vs init (iguales = host PID ns) --"; readlink /proc/self/ns/pid 2>/dev/null; readlink /proc/1/ns/pid 2>/dev/null; cat /proc/1/comm 2>/dev/null

      echo "## 2. capabilities / seccomp / apparmor"
      grep -E 'CapEff|CapBnd|CapPrm|NoNewPrivs|Seccomp' /proc/self/status 2>/dev/null
      echo "   (CapEff=0000003fffffffff => privilegiado; Seccomp:0 => sin filtro; NoNewPrivs:0 => setuid permitido)"
      command -v capsh >/dev/null 2>&1 && capsh --decode=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}') 2>/dev/null
      echo "-- apparmor (unconfined = red flag) --"; cat /proc/self/attr/current 2>/dev/null

      echo "## 3. dispositivos de host (bloque visible = privilegiado)"
      ls /dev 2>/dev/null | grep -E '^(sd|vd|xvd|nvme|dm-)' | head

      echo "## 4. mounts del host / sockets (solo presencia, NO conectar)"
      grep -E 'docker.sock|containerd.sock|crio.sock|kubelet|/var/lib/docker|/proc/1/root|/host(/| )|serviceaccount' /proc/self/mountinfo 2>/dev/null | head -20
      for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do [ -S "$s" ] && echo "SOCKET_PRESENTE $(ls -l "$s" 2>/dev/null)"; done

      echo "## 5. kubernetes (presencia; NO imprimir el token)"
      test -f /var/run/secrets/kubernetes.io/serviceaccount/token && echo "SA_TOKEN_PRESENTE"
      cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null
      env | grep -E '^KUBERNETES_SERVICE_(HOST|PORT)=' 2>/dev/null
      if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        echo -n "kube-api /version (sin token) HTTP="; curl -sk -m 4 -o /dev/null -w '%%{http_code}\n' "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/version" 2>/dev/null
      fi

      echo "## 6. cloud metadata (IMDS) — SOLO nombre de rol, NO el cuerpo de credenciales"
      AWST=$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)
      echo -n "AWS roles: "; curl -s -m 3 -H "X-aws-ec2-metadata-token: $AWST" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -3; echo
      echo "   (si lista un rol => el host tiene credenciales IAM alcanzables. PARAR aquí, NO pedir .../ <rol>)"
      echo -n "GCP SAs: "; curl -s -m 3 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ 2>/dev/null | head -3; echo
      echo -n "Azure IMDS HTTP="; curl -s -m 3 -o /dev/null -w '%%{http_code}\n' -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null

      echo "## 7. indicadores de escape (SOLO permisos; NO escribir)"
      stat -c '%A %U %n' /proc/sys/kernel/core_pattern 2>/dev/null
      find /sys/fs/cgroup -name release_agent 2>/dev/null | head | while read f; do stat -c '%A %n' "$f" 2>/dev/null; done
      echo "-- raiz del host vía /proc/1/root (¿legible?) --"; ls -la /proc/1/root 2>/dev/null | head -5; test -r /proc/1/root/etc/shadow && echo "HOST_SHADOW_LEGIBLE!!"

      echo "===== fin probe — si aparece SA_TOKEN/SOCKET/HOST_SHADOW/rol IAM/host mounts => PARAR y documentar PoC mínima ====="
    EOT
  }
}
