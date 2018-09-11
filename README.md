# re-scripts
IDA, Radare2 and Bninja scripts

## Radare2 scripts
- Install `r2pipe`

### fnd-native-on-apks.py
```c
[00:52 edu@de11 r2] > python3 fnd-native-on-apks.py classes.dex
Lktnznvzk/B8JGragL;->e0BKigvZ(Ljava/lang/String;)V
Lktnznvzk/B8JGragL;->kQlvThOX(I)Ljava/lang/String;
Lktnznvzk/GQXHPoH2;->Ii4wCzIb(Landroid/content/Context;Lktnznvzk/CcHdfDwq;)V
Lktnznvzk/GQXHPoH2;->dVZw9Ic4()V
Lktnznvzk/WPhrgsA0;->m4oevkMk(Landroid/content/Context;Landroid/app/Instrumentation;)V
Lktnznvzk/cfjzcnFw;->bl8u_2BW(Landroid/content/Context;)Ljava/lang/String;
Lktnznvzk/cfjzcnFw;->iBC2p5jZ(Landroid/content/Context;)Z
Lktnznvzk/cfjzcnFw;->mgu8vTph(Landroid/content/Context;)V
Lktnznvzk/m6xY5gLT;->SzE3mfpa(Z)V
Lktnznvzk/nmlzScff;->HRYjrbFM(Landroid/app/Activity;)V
Lktnznvzk/nmlzScff;->Wp1IXxUR(Landroid/app/Activity;)V
Lktnznvzk/nmlzScff;->ddKwoTnK(Landroid/app/Activity;)V
Lktnznvzk/nmlzScff;->lAfxDkdQ()V
Lktnznvzk/nmlzScff;->zwaFeGH7()V
>> JNI [14 natives/54313 methods/7539 classes] <<
```
