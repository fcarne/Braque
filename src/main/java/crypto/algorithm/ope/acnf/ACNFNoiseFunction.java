package crypto.algorithm.ope.acnf;

import org.apache.commons.math3.analysis.UnivariateFunction;

public class ACNFNoiseFunction implements UnivariateFunction {

    byte[] a;

    public ACNFNoiseFunction(byte[] a) {
        if (a.length != 10) throw new IllegalArgumentException();
        this.a = a;
    }

    @Override
    public double value(double t) {
        return (a[0] + a[1] * t + a[2] * Math.pow(t, 2)) * (a[3] + a[4] * Math.sin(a[5] + a[6] * t) + a[7] * Math.cos(a[8] + a[9] * t));
    }
}
