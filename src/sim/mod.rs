mod network;
pub mod clock;
mod simulation;

pub use simulation::Simulation;
pub use network::ChannelParameters;
pub use network::Endpoint;
pub use network::ChannelMessage;

pub fn opt_min<T : Ord + Copy>(opt_values: &[Option<T>]) -> Option<T> {
    let mut opt_res: Option<T> = None;
    for opt_val in opt_values.iter() {
        match (opt_val, opt_res) {
            (None, _) => (),
            (Some(val), None) => opt_res = Some(*val),
            (Some(val), Some(res)) => opt_res = Some(std::cmp::min(res, *val)),
        }
    }
    opt_res
}
