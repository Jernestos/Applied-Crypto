import numpy as np


def row_echelon_form(M: np.ndarray, p: int):
    lead = 0
    rowCount = len(M)
    columnCount = len(M[0])
    for r in range(rowCount):
        if lead >= columnCount:
            return
        i = r
        while M[i][lead] == 0:
            i += 1
            if i == rowCount:
                i = r
                lead += 1
                if columnCount == lead:
                    return

        M[i], M[r] = M[r], M[i].copy()

        lv = M[r][lead]
        M[r] = [(pow(lv, -1, p) * mrx) % p for mrx in M[r]]
        for i in range(rowCount):
            if i != r:
                lv = M[i][lead]
                M[i] = [(iv - lv * rv) % p for rv, iv in zip(M[r], M[i])]
        lead += 1
    return M
