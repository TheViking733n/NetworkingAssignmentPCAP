#include <bits/stdc++.h>

using namespace std;

int main(int argc, char *argv[])
{
    int n = 5;

    vector<int> arr(n);
    for (auto &i : arr)
    {
        cin >> i;
    }
    int sm = 0;
    for (auto i : arr)
    {
        sm += i;
    }

    cout << sm << endl;

    return 0;
}