#[derive(Clone)]
pub struct FeatureStats {
    total: f64,
    min: f64,
    max: f64,
    mean: f64,
    std: f64,
    count: u32,
}

impl FeatureStats {
    pub fn new() -> Self {
        Self {
            total: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            mean: 0.0,
            std: 0.0,
            count: 0,
        }
    }

    pub fn get_total(&self) -> f64 {
        self.total
    }

    pub fn get_min(&self) -> f64 {
        if self.count > 0 {
            self.min
        } else {
            0.0
        }
    }

    pub fn get_max(&self) -> f64 {
        if self.count > 0 {
            self.max
        } else {
            0.0
        }
    }

    pub fn get_mean(&self) -> f64 {
        self.mean
    }

    pub fn get_std(&self) -> f64 {
        self.std
    }

    pub fn get_count(&self) -> u32 {
        self.count
    }

    fn update_mean(&mut self, value: f64) {
        self.mean = (((self.count - 1) as f64 * self.mean) + value) / self.count as f64;
    }

    fn update_std(&mut self, value: f64, old_mean: f64) {
        self.std = ((((self.count - 1) as f64 * self.std.powf(2.0))
            + ((value - old_mean) * (value - self.mean)))
            / self.count as f64)
            .sqrt();
    }

    fn update_min(&mut self, value: f64) {
        if value < self.min {
            self.min = value;
        }
    }

    fn update_max(&mut self, value: f64) {
        if value > self.max {
            self.max = value;
        }
    }

    pub fn add_value(&mut self, value: f64) {
        self.count += 1;
        self.total += value;
        self.update_min(value);
        self.update_max(value);
        let old_mean: f64 = self.mean;
        self.update_mean(value);
        self.update_std(value, old_mean);
    }

    pub fn dump_headers(prefix: &str) -> String {
        format!("{prefix}_total,{prefix}_mean,{prefix}_std,{prefix}_max,{prefix}_min")
    }

    pub fn dump_values(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.get_total(),
            self.get_mean(),
            self.get_std(),
            self.get_max(),
            self.get_min(),
        )
    }
}
