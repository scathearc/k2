//! PID feedback loops for smooth rate adjustments.

/// Converges the *actual* observed rate onto the commanded target, damping
/// oscillation between scheduler command and worker throughput.
#[derive(Debug)]
pub struct Pid {
    kp: f64,
    ki: f64,
    kd: f64,
    integral: f64,
    last_err: Option<f64>,
    out_min: f64,
    out_max: f64,
}

impl Pid {
    pub fn new(kp: f64, ki: f64, kd: f64, out_min: f64, out_max: f64) -> Self {
        Self {
            kp,
            ki,
            kd,
            integral: 0.0,
            last_err: None,
            out_min,
            out_max,
        }
    }

    pub fn reset(&mut self) {
        self.integral = 0.0;
        self.last_err = None;
    }

    /// `setpoint` = commanded rate; `measurement` = realized rate. Returns the
    /// correction (added to the base target).
    pub fn step(&mut self, setpoint: f64, measurement: f64, dt_s: f64) -> f64 {
        if dt_s <= 0.0 {
            return 0.0;
        }
        let err = setpoint - measurement;
        self.integral = (self.integral + err * dt_s).clamp(-1e6, 1e6);
        let d = match self.last_err {
            Some(e) => (err - e) / dt_s,
            None => 0.0,
        };
        self.last_err = Some(err);
        let out = self.kp * err + self.ki * self.integral + self.kd * d;
        out.clamp(self.out_min, self.out_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proportional_pull() {
        let mut p = Pid::new(0.1, 0.0, 0.0, -1000.0, 1000.0);
        let c = p.step(1000.0, 900.0, 0.1);
        assert!((c - 10.0).abs() < 1e-6, "got {c}");
    }

    #[test]
    fn integral_accumulates() {
        let mut p = Pid::new(0.0, 0.5, 0.0, -10_000.0, 10_000.0);
        let _ = p.step(1000.0, 500.0, 0.1); // err 500, I = 50
        let c = p.step(1000.0, 500.0, 0.1); // err 500, I = 100
        assert!((c - 50.0).abs() < 1e-6, "got {c}");
    }

    #[test]
    fn derivative_counteracts() {
        let mut p = Pid::new(0.0, 0.0, 0.5, -10_000.0, 10_000.0);
        let _ = p.step(1000.0, 500.0, 0.1);
        let c2 = p.step(1000.0, 900.0, 0.1); // err shrank: negative derivative
        assert!(c2 < 0.0, "got {c2}");
    }

    #[test]
    fn output_clamps() {
        let mut p = Pid::new(1.0, 0.0, 0.0, -5.0, 5.0);
        let c = p.step(1e9, 0.0, 0.1);
        assert_eq!(c, 5.0);
        let c = p.step(-1e9, 0.0, 0.1);
        assert_eq!(c, -5.0);
    }
}
