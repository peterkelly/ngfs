use torrent::util::detrand::Generator;

fn main() {
    let mut gen = Generator::new(12345);

    let mut frequency: [usize; 32] = [0; 32];
    for _ in 0..100000 {
        let v = gen.next();
        print!("{:08x} ", v);

        for i in 0..32 {
            if (v >> (31 - i)) & 1 == 1{
                print!("1");
                frequency[i] += 1;
            }
            else {
                print!("0");
            }
        }
        println!();
    }
    for i in 0..32 {
        println!("frequency[{:02}] = {}", i, frequency[i]);
    }
}
